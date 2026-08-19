package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/vphpersson/tpm_signer/pkg/keyfile"
)

// publicArea builds a marshalled TPM2B_PUBLIC for an RSA modulus, so the parts of this package
// that run before the TPM is touched can be tested without hardware.
func publicArea(t *testing.T, modulus []byte) []byte {
	t.Helper()

	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
			KeyBits: 2048,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: modulus}),
	})

	return tpm2.Marshal(&public)
}

func testKey(t *testing.T) *keyfile.Key {
	t.Helper()

	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	private := tpm2.TPM2BPrivate{Buffer: []byte{0xde, 0xad, 0xbe, 0xef}}

	return &keyfile.Key{
		Parent:  ownerHierarchy,
		Public:  publicArea(t, software.N.Bytes()),
		Private: tpm2.Marshal(&private),
	}
}

func TestPublicKey(t *testing.T) {
	t.Parallel()

	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	testCases := []struct {
		name      string
		key       *keyfile.Key
		expectErr bool
		wantN     *big.Int
	}{
		{
			name:  "valid",
			key:   &keyfile.Key{Public: publicArea(t, software.N.Bytes())},
			wantN: software.N,
		},
		{name: "nil key", key: nil, expectErr: true},
		{name: "empty public area", key: &keyfile.Key{}, expectErr: true},
		{name: "garbage public area", key: &keyfile.Key{Public: []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04}}, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			publicKey, err := PublicKey(testCase.key)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if publicKey.N.Cmp(testCase.wantN) != 0 {
				t.Error("modulus does not match the one in the public area")
			}
			if publicKey.E != 65537 {
				t.Errorf("exponent = %d, want 65537", publicKey.E)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	provider := func() ([]byte, error) { return []byte("123456"), nil }

	testCases := []struct {
		name        string
		key         *keyfile.Key
		devicePath  string
		pinProvider PINProvider
		expectErr   bool
	}{
		{name: "valid", key: key, devicePath: DefaultDevicePath, pinProvider: provider},
		{
			name:       "no pin provider is fine for an empty auth key",
			key:        &keyfile.Key{Parent: ownerHierarchy, EmptyAuth: true, Public: key.Public, Private: key.Private},
			devicePath: DefaultDevicePath,
		},
		{name: "nil key", devicePath: DefaultDevicePath, pinProvider: provider, expectErr: true},
		{name: "empty device path", key: key, pinProvider: provider, expectErr: true},
		{name: "pin required but no provider", key: key, devicePath: DefaultDevicePath, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(testCase.key, testCase.devicePath, testCase.pinProvider)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestSignRejectsUnsupportedOptions covers the argument checks, which run before the TPM is
// opened and so need no hardware.
func TestSignRejectsUnsupportedOptions(t *testing.T) {
	t.Parallel()

	signer, err := New(testKey(t), DefaultDevicePath, func() ([]byte, error) { return []byte("123456"), nil })
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	digest := sha256.Sum256([]byte("payload"))

	testCases := []struct {
		name   string
		digest []byte
		opts   crypto.SignerOpts
	}{
		{name: "nil opts", digest: digest[:], opts: nil},
		{name: "pss is not supported", digest: digest[:], opts: &rsa.PSSOptions{Hash: crypto.SHA256}},
		{name: "wrong hash", digest: digest[:], opts: crypto.SHA512},
		{name: "short digest", digest: digest[:16], opts: crypto.SHA256},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := signer.Sign(rand.Reader, testCase.digest, testCase.opts); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

// TestLive exercises the real chip. It is opt in because it generates a key, which takes seconds,
// and because the wrong-PIN case deliberately increments the TPM's dictionary attack counter.
//
//	TPM_SIGNER_LIVE=1 go test ./pkg/signer/ -run TestLive -v
func TestLive(t *testing.T) { //nolint:paralleltest // Drives the real TPM, which is a single shared device.
	if os.Getenv("TPM_SIGNER_LIVE") != "1" {
		t.Skip("set TPM_SIGNER_LIVE=1 to run against the real TPM")
	}

	pin := []byte("482913")

	created, err := CreateKey(DefaultDevicePath, pin, "test@capa")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if created.EmptyAuth {
		t.Error("a key created with a PIN must not be marked empty auth")
	}

	encoded, err := created.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	key, err := keyfile.Parse(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	signer, err := New(key, DefaultDevicePath, func() ([]byte, error) { return pin, nil })
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	publicKey, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatal("public key is not RSA")
	}

	digest := sha256.Sum256([]byte("hello from the tpm"))

	start := time.Now()
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	t.Logf("signed in %v", time.Since(start).Round(time.Millisecond))

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	t.Run("wrong pin is refused", func(t *testing.T) { //nolint:paralleltest // Shares the TPM, as above.
		wrong, err := New(key, DefaultDevicePath, func() ([]byte, error) { return []byte("000000"), nil })
		if err != nil {
			t.Fatalf("new signer: %v", err)
		}
		if _, err := wrong.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
			t.Error("a wrong PIN produced a signature")
		}
	})
}
