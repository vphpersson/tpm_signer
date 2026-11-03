package gcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/altshiftab/utils_go/pkg/oauth2/types/token_source"
	"github.com/google/go-tpm/tpm2"

	"github.com/vphpersson/tpm_signer/pkg/keyfile"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

// A software key stands in for the TPM's: the package takes a crypto.Signer, so
// everything above the chip is testable without one.
func testSigner(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

// mintingServer answers every exchange with a token, and counts how many it was
// asked for.
func mintingServer(t *testing.T, expiresIn int) (*Client, func() int) {
	t.Helper()

	var mutex sync.Mutex
	var mints int

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		mutex.Lock()
		mints++
		issued := mints
		mutex.Unlock()

		writer.Header().Set("Content-Type", "application/json")
		if err := json.MarshalWrite(writer, map[string]any{
			"access_token": fmt.Sprintf("token-%d", issued),
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		}); err != nil {
			t.Errorf("marshal write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	return &Client{Endpoint: server.URL}, func() int {
		mutex.Lock()
		defer mutex.Unlock()
		return mints
	}
}

// newTestMinter is the minting half on its own, which mints every time it is
// asked.
func newTestMinter(t *testing.T, client *Client) *tokenMinter {
	t.Helper()

	return &tokenMinter{
		ctx:            t.Context(),
		signer:         testSigner(t),
		client:         client,
		serviceAccount: "poller@example.iam.gserviceaccount.com",
		scopes:         []string{ScopeCloudPlatform},
	}
}

// newTestTokenSource is the whole thing as NewTokenSource composes it, minus
// the key file a real one reads.
func newTestTokenSource(t *testing.T, client *Client) token_source.TokenSource {
	t.Helper()

	minter := newTestMinter(t, client)
	return newTokenSource(minter.ctx, minter.signer, minter.client, minter.serviceAccount, minter.scopes)
}

func TestTokenSourceMintsOnceWhileValid(t *testing.T) {
	t.Parallel()

	client, mints := mintingServer(t, 3600)
	source := newTestTokenSource(t, client)

	first, err := source.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if first.AccessToken == "" {
		t.Fatal("no access token")
	}
	if first.Type() != "Bearer" {
		t.Errorf("token type = %q, want Bearer", first.Type())
	}

	// An hour of life left, so nothing should go back to the TPM or the
	// endpoint for it.
	for range 5 {
		again, err := source.Token()
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if again.AccessToken != first.AccessToken {
			t.Errorf("token = %q, want the one already held (%q)", again.AccessToken, first.AccessToken)
		}
	}

	if got := mints(); got != 1 {
		t.Errorf("mints = %d, want 1", got)
	}
}

func TestTokenSourceMintsAgainWhenSpent(t *testing.T) {
	t.Parallel()

	// A token already expired when it arrives, so every call finds it spent.
	// This is the case a daemon meets after an hour, which is the whole reason
	// the source exists.
	client, mints := mintingServer(t, -1)
	source := newTestTokenSource(t, client)

	first, err := source.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	second, err := source.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	if second.AccessToken == first.AccessToken {
		t.Error("the spent token was handed out again")
	}
	if got := mints(); got != 2 {
		t.Errorf("mints = %d, want 2", got)
	}
}

func TestTokenSourceMintsOnceUnderConcurrentCallers(t *testing.T) {
	t.Parallel()

	client, mints := mintingServer(t, 3600)
	source := newTestTokenSource(t, client)

	var waitGroup sync.WaitGroup
	for range 16 {
		waitGroup.Go(func() {
			if _, err := source.Token(); err != nil {
				t.Errorf("token: %v", err)
			}
		})
	}
	waitGroup.Wait()

	// A signature costs the TPM about half a second; a burst must not cost
	// sixteen of them.
	if got := mints(); got != 1 {
		t.Errorf("mints = %d, want 1", got)
	}
}

func TestTokenSourceRefusesACancelledContext(t *testing.T) {
	t.Parallel()

	client, mints := mintingServer(t, 3600)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	minter := newTestMinter(t, client)
	minter.ctx = ctx

	if _, err := token_source.NewReusable(nil, minter).Token(); err == nil {
		t.Error("expected an error")
	}
	if got := mints(); got != 0 {
		t.Errorf("mints = %d, want 0", got)
	}
}

// writeKeyFile writes a no-PIN key file around a software key's public half, enough for
// NewTokenSource to load: nothing touches the TPM until the first token is asked for.
func writeKeyFile(t *testing.T, keyType signer.KeyType) string {
	t.Helper()

	template, err := signer.KeyTemplate(keyType, true)
	if err != nil {
		t.Fatalf("key template: %v", err)
	}

	switch keyType {
	case signer.KeyTypeRSA2048:
		template.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: testSigner(t).N.Bytes()})
	case signer.KeyTypeECCP256:
		software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		point, err := software.PublicKey.Bytes()
		if err != nil {
			t.Fatalf("public key bytes: %v", err)
		}
		template.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: point[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: point[33:]},
		})
	default:
		t.Fatalf("no key file for %s", keyType)
	}

	public := tpm2.New2B(*template)
	private := tpm2.TPM2BPrivate{Buffer: []byte{0xde, 0xad, 0xbe, 0xef}}
	encoded, err := (&keyfile.Key{
		EmptyAuth: true,
		Parent:    0x40000001,
		Public:    tpm2.Marshal(&public),
		Private:   tpm2.Marshal(&private),
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal key file: %v", err)
	}

	path := filepath.Join(t.TempDir(), string(keyType)+".tpm")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	return path
}

func TestNewTokenSource(t *testing.T) {
	t.Parallel()

	rsaKeyPath := writeKeyFile(t, signer.KeyTypeRSA2048)
	eccKeyPath := writeKeyFile(t, signer.KeyTypeECCP256)

	testCases := []struct {
		name    string
		options *TokenSourceOptions
		wantErr bool
	}{
		{name: "no options", wantErr: true},
		{
			name:    "no key path",
			options: &TokenSourceOptions{ServiceAccount: "a@example.iam.gserviceaccount.com"},
			wantErr: true,
		},
		{
			name:    "no service account",
			options: &TokenSourceOptions{KeyPath: "/nonexistent"},
			wantErr: true,
		},
		{
			name: "an rsa key file",
			options: &TokenSourceOptions{
				KeyPath:        rsaKeyPath,
				ServiceAccount: "a@example.iam.gserviceaccount.com",
			},
		},
		{
			name: "an ecc key file is refused at construction",
			options: &TokenSourceOptions{
				KeyPath:        eccKeyPath,
				ServiceAccount: "a@example.iam.gserviceaccount.com",
			},
			wantErr: true,
		},
		{
			name: "a key file that is not there",
			options: &TokenSourceOptions{
				KeyPath:        "/nonexistent/gcp.tpm",
				ServiceAccount: "a@example.iam.gserviceaccount.com",
			},
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewTokenSource(t.Context(), testCase.options); (err != nil) != testCase.wantErr {
				t.Errorf("error = %v, want an error: %v", err, testCase.wantErr)
			}
		})
	}
}
