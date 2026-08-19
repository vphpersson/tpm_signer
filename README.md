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

## Why RSA

Google accepts only RSA service account keys and signs assertions only with RS256, so the key is RSA-2048 despite P-256 being faster and pleasanter in every other respect. Key creation takes a few seconds; each signature takes about half a second on an AMD fTPM. That is once per hour in practice, since tokens are cached until they expire.

## Use

Create the key. This is the only interactive step, and it asks for a PIN twice:

```sh
tpm-keygen --subject tpm-signer-altshift
```

It writes two files: `gcp.tpm`, the key, useless anywhere else; and `gcp.crt`, a self-signed certificate carrying the public half, which is the shape Google's upload endpoint wants. The certificate's validity bounds the uploaded key's life, so `--days` is a real expiry rather than decoration.

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

## The PIN

The PIN is the key's TPM auth value, not a passphrase over an encrypted file. It is never sent to the chip in the clear: the session is salted to the storage root key and encrypts command parameters, so the PIN only ever keys an HMAC.

Because the key is created with `NoDA` false, it sits under the TPM's dictionary attack lockout. On the machine this was developed against:

| parameter | value |
| --- | --- |
| failures before lockout | 31 |
| one failure forgiven every | 10 minutes |
| lockout recovery | 24 hours |

That is roughly 144 guesses per day after the initial allowance, which is what makes a six-digit PIN defensible here in a way a six-character password would not be anywhere else. Read the values for a given chip with `TestDAParams`-style `GetCapability` calls rather than assuming these.

A PIN defends against something running in the background as you. It does not defend against an attacker who is already present and can keylog it, or who waits until you have entered it and uses the loaded key. `--no-pin` is available and matches how `ssh-tpm-agent` keys are normally configured; it is the right choice when the threat is a stolen laptop rather than local malware.

## Tests

```sh
go test ./...                                             # no hardware needed
TPM_SIGNER_LIVE=1 go test ./pkg/signer/ -run TestLive -v   # drives the real chip
```

The live test is opt-in because it generates a key, which takes seconds, and because its wrong-PIN case deliberately increments the dictionary attack counter.
