# tpm_signer

A `crypto.Signer` backed by a key that lives inside the TPM, and a Google Cloud token minter built on it.

The point is to remove permanent, portable secrets from disk. A service account JSON file, or a `gcloud` refresh token, is a bearer credential: whoever copies the file can use it from anywhere until it is revoked. A TPM key cannot be copied. It is created inside the chip with `fixedTPM` set, so the private half has no exit path from the hardware, and the file on disk is a wrapped blob that is inert on any other machine.

## What it is not

The access token this mints is still a bearer token. It lives in RAM and in the environment for up to an hour, and it can be replayed by anything that lifts it during that window. What the TPM buys is that there is no permanent secret at rest, and nothing on disk works on another machine. Closing the remaining gap needs certificate-bound tokens (RFC 8705), which is a much larger piece of machinery.

## Layout

| package | role |
| --- | --- |
| `pkg/keyfile` | The TCG "TPM 2.0 Key Files" ASN.1 container, hand-rolled on `encoding/asn1`. Round-trips byte-identically against keys written by `ssh-tpm-agent`. |
| `pkg/signer` | Key creation and `crypto.Signer`. The only package that knows a TPM exists. |
| `pkg/gcp` | Assertion signing and the token exchange. Takes a `crypto.Signer`, so it is testable with a software key. |
| `pkg/pin` | PIN entry, delegated to `systemd-ask-password`. |

The boundary between `pkg/signer` and `pkg/gcp` is stdlib `crypto.Signer`. Nothing above the signer depends on TPM code, which is why the same assertion logic would serve a YubiKey, a PKCS#11 token, or a file-based key without modification.

## Key types

`tpm-keygen --type` picks one of two:

| type | for | |
| --- | --- | --- |
| `rsa-2048` (default) | Google | Google accepts only RSA service account keys and signs assertions only with RS256. |
| `ecc-p256` | ES256, anywhere else | Quicker to create, and a signature is 70-odd bytes rather than 256. |

Both are created with a null scheme, and `Sign` chooses at sign time: RSASSA-PKCS1-v1_5 or ECDSA, over a SHA-256 digest either way. An ECDSA signature comes back ASN.1 DER encoded, as `crypto.Signer` requires and as `ecdsa.VerifyASN1` and `crypto/x509` read it; a JWS wants the fixed-width `r || s` instead, and converting is the caller's job, as it is for any other `crypto.Signer`. `gcp.Assertion` refuses a non-RSA signer up front rather than let Google refuse the result.

Timings, per operation, including re-deriving the storage root key each time:

| chip | create RSA | create P-256 | sign RSA | sign P-256 |
| --- | --- | --- | --- | --- |
| capa, AMD fTPM | ~4.2 s | not measured | ~0.5 s | not measured |
| saviour, Infineon discrete | ~1.3 s | ~1.0 s | ~1.4 s | ~1.2 s |

## Use

Create the key. This is the only interactive step, and it asks for a PIN twice:

```sh
tpm-keygen --subject tpm-signer-altshift
```

It writes two files: `gcp.tpm`, the key, useless anywhere else; and `gcp.crt`, a self-signed certificate carrying the public half, which is the shape Google's upload endpoint wants. The certificate's validity bounds the uploaded key's life, so `--days` is a real expiry rather than decoration. `--public-key-file` writes the public half a third time, as a PKIX `PUBLIC KEY` PEM.

`tpm-keygen` never overwrites a file. A key's public half may already be registered somewhere, and a second key in its place would lose the first for good; an old certificate overwritten by a new one would have the next upload register the wrong key. Every output path is checked before the PIN is asked for, and a run that fails part-way removes what it wrote, so it leaves no key file whose public half went nowhere.

An ECC key for something unattended, exporting the public half where a service registering API keys wants it:

```sh
tpm-keygen --type ecc-p256 --no-pin \
    --key-file ~/.config/tpm-signer/job.tpm \
    --public-key-file ~/.config/tpm-signer/job.pub.pem
```

An ECC key gets no certificate unless `--cert-file` is given, since Google would refuse it; one of the two output files is required, or there would be no way to get the public half out.

Register the public half against a service account:

```sh
gcloud iam service-accounts keys upload gcp.crt --iam-account=SERVICE_ACCOUNT
```

Then mint tokens:

```sh
export GOOGLE_OAUTH_ACCESS_TOKEN="$(gcp-token -a SERVICE_ACCOUNT)"
terraform plan
```

`gcloud` reads the same token from `CLOUDSDK_AUTH_ACCESS_TOKEN`. Tokens are cached under `XDG_RUNTIME_DIR`, which is tmpfs, so the PIN is asked for roughly once an hour rather than once per command, and nothing survives a reboot.

## In a long-running program

`gcp-token` suits a command line: mint a token, run one thing, exit. A daemon needs more, because a token lasts an hour and one handed to it at startup stops working an hour later. The usual answer is to give the process a service account key file instead -- which is the bearer credential this exists to remove.

`gcp.NewTokenSource` is the other shape. It satisfies utils_go's `token_source.TokenSource`, so it drops into anything that already takes one, and it mints again when the token it holds has run down:

```go
tokenSource, err := gcp.NewTokenSource(ctx, &gcp.TokenSourceOptions{
    KeyPath:        "/etc/tpm-signer/poller.tpm",
    ServiceAccount: "poller@project.iam.gserviceaccount.com",
    Scopes:         []string{"https://www.googleapis.com/auth/pubsub"},
})
```

What it returns is a minter wrapped in utils_go's `NewReusable`, which is where every other token source in that library leaves the question: reuse and the mutex around it are already written there, and a source that cached on its own would be a second copy of them. So a burst of callers costs one signature rather than one each -- which matters, since a signature is about half a second on an fTPM.

The signer opens the TPM per signature and closes it again, so holding the source for the life of a process holds no handle on the device.

Under systemd this wants `SupplementaryGroups=tss` or membership in that group, and in a container `AddDevice=/dev/tpmrm0`. Use a key created with `--no-pin`: nothing can answer a prompt at three in the morning.

## The PIN

The PIN is the key's TPM auth value, not a passphrase over an encrypted file. It is never sent to the chip in the clear: the session is salted to the storage root key and encrypts command parameters, so the PIN only ever keys an HMAC.

Because a key with a PIN is created with `NoDA` false, it sits under the TPM's dictionary attack lockout. On the machines it runs on:

| parameter | capa (AMD fTPM) | saviour (Infineon) |
| --- | --- | --- |
| failures before lockout | 31 | 32 |
| one failure forgiven every | 10 minutes | 2 hours |
| lockout recovery | 24 hours | 24 hours |

That is roughly 144 guesses per day on capa after the initial allowance, which is what makes a six-digit PIN defensible here in a way a six-character password would not be anywhere else. Read the values for a given chip with `GetCapability` on `TPM_PT_MAX_AUTH_FAIL` and its neighbours rather than assuming these.

A key made with `--no-pin` is created with `NoDA` set instead. With no auth value there is nothing to guess, so the lockout would protect nothing, and it would let failed PINs against other keys on the same chip lock an unattended job out for a day.

A PIN defends against something running in the background as you. It does not defend against an attacker who is already present and can keylog it, or who waits until you have entered it and uses the loaded key. `--no-pin` is available and matches how `ssh-tpm-agent` keys are normally configured; it is the right choice when the threat is a stolen laptop rather than local malware.

## Tests

```sh
go test ./...                                             # no hardware needed
TPM_SIGNER_LIVE=1 go test ./pkg/signer/ -run TestLive -v   # drives the real chip
```

The live test is opt-in because it generates a key of each kind, which takes seconds, and because its wrong-PIN case deliberately increments the dictionary attack counter; `-skip 'TestLive/.*/wrong_pin'` leaves the counter alone on a chip that other things depend on.
