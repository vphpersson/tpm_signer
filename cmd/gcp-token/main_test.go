package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/vphpersson/tpm_signer/pkg/gcp"
	"github.com/vphpersson/tpm_signer/pkg/keyfile"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

// errMintFailed stands in for whatever stops a mint: a wrong PIN, a refused assertion.
var errMintFailed = errors.New("mint failed")

const (
	testServiceAccount = "robot@project.iam.gserviceaccount.com"
	testReadOnlyScope  = "https://www.googleapis.com/auth/devstorage.read_only"
)

func TestEmit(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		token      string
		exportForm bool
		want       string
	}{
		{name: "bare token", token: "ya29.test", want: "ya29.test\n"},
		{
			name:       "export statement",
			token:      "ya29.test",
			exportForm: true,
			want:       "export GOOGLE_OAUTH_ACCESS_TOKEN=ya29.test\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			emit(&output, testCase.token, testCase.exportForm)

			if output.String() != testCase.want {
				t.Errorf("emitted %q, want %q", output.String(), testCase.want)
			}
			// A stray newline inside the value would corrupt the shell assignment.
			if strings.Count(output.String(), "\n") != 1 {
				t.Errorf("expected exactly one newline, got %q", output.String())
			}
		})
	}
}

func TestDefaultKeyPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		want string
	}{
		{name: "ends at the key file", want: "gcp.tpm"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			path := defaultKeyPath()
			if filepath.Base(path) != testCase.want {
				t.Errorf("path %q does not end in %q", path, testCase.want)
			}
		})
	}
}

// testKey is a key file around a software key's public half: enough for the cache, which hashes
// the public key, and nothing here signs with it.
func testKey(t *testing.T) *keyfile.Key {
	t.Helper()

	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template, err := signer.KeyTemplate(signer.KeyTypeRSA2048, false)
	if err != nil {
		t.Fatalf("key template: %v", err)
	}
	template.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: software.N.Bytes()})

	public := tpm2.New2B(*template)
	private := tpm2.TPM2BPrivate{Buffer: []byte{0xde, 0xad, 0xbe, 0xef}}

	return &keyfile.Key{
		Parent:  0x40000001,
		Public:  tpm2.Marshal(&public),
		Private: tpm2.Marshal(&private),
	}
}

// countingMinter hands out a new token each time it is called, and counts the calls: each one is
// a PIN prompt and a TPM signature in the real thing.
func countingMinter() (minter, *int) {
	calls := 0
	return func() (*gcp.Token, error) {
		calls++
		return &gcp.Token{
			AccessToken: "ya29.minted-" + strings.Repeat("x", calls),
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(time.Hour),
		}, nil
	}, &calls
}

// TestTokenFor runs two requests against one cache in turn, and counts what each had to mint.
//
//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestTokenFor(t *testing.T) {
	key := testKey(t)
	otherKey := testKey(t)
	broad := []string{gcp.ScopeCloudPlatform}

	testCases := []struct {
		name        string
		first       *config
		firstKey    *keyfile.Key
		second      *config
		secondKey   *keyfile.Key
		wantMints   int
		wantSameJWT bool
	}{
		{
			name:        "the same request is answered from the cache",
			first:       &config{serviceAccount: testServiceAccount, scopes: broad},
			firstKey:    key,
			second:      &config{serviceAccount: testServiceAccount, scopes: broad},
			secondKey:   key,
			wantMints:   1,
			wantSameJWT: true,
		},
		{
			name:      "a narrower scope is not answered with a cloud-platform token",
			first:     &config{serviceAccount: testServiceAccount, scopes: broad},
			firstKey:  key,
			second:    &config{serviceAccount: testServiceAccount, scopes: []string{testReadOnlyScope}},
			secondKey: key,
			wantMints: 2,
		},
		{
			name:      "a cloud-platform request is not answered with a narrow token",
			first:     &config{serviceAccount: testServiceAccount, scopes: []string{testReadOnlyScope}},
			firstKey:  key,
			second:    &config{serviceAccount: testServiceAccount, scopes: broad},
			secondKey: key,
			wantMints: 2,
		},
		{
			name:      "another key mints its own",
			first:     &config{serviceAccount: testServiceAccount, scopes: broad},
			firstKey:  key,
			second:    &config{serviceAccount: testServiceAccount, scopes: broad},
			secondKey: otherKey,
			wantMints: 2,
		},
		{
			name:      "no cache mints every time",
			first:     &config{serviceAccount: testServiceAccount, scopes: broad, noCache: true},
			firstKey:  key,
			second:    &config{serviceAccount: testServiceAccount, scopes: broad, noCache: true},
			secondKey: key,
			wantMints: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			mint, calls := countingMinter()

			first, err := tokenFor(testCase.first, testCase.firstKey, mint, io.Discard)
			if err != nil {
				t.Fatalf("first: %v", err)
			}
			second, err := tokenFor(testCase.second, testCase.secondKey, mint, io.Discard)
			if err != nil {
				t.Fatalf("second: %v", err)
			}

			if *calls != testCase.wantMints {
				t.Errorf("minted %d times, want %d", *calls, testCase.wantMints)
			}
			if (first.AccessToken == second.AccessToken) != testCase.wantSameJWT {
				t.Errorf("tokens %q and %q: same = %v, want %v",
					first.AccessToken, second.AccessToken, first.AccessToken == second.AccessToken, testCase.wantSameJWT)
			}
		})
	}
}

//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestTokenForErrors(t *testing.T) {
	key := testKey(t)

	testCases := []struct {
		name string
		cfg  *config
		key  *keyfile.Key
		mint minter
	}{
		{
			name: "a failed mint is reported",
			cfg:  &config{serviceAccount: testServiceAccount, scopes: []string{gcp.ScopeCloudPlatform}},
			key:  key,
			mint: func() (*gcp.Token, error) { return nil, errMintFailed },
		},
		{
			name: "a mint that yields nothing is refused",
			cfg:  &config{serviceAccount: testServiceAccount, scopes: []string{gcp.ScopeCloudPlatform}},
			key:  key,
			mint: func() (*gcp.Token, error) { return nil, nil },
		},
		{
			name: "no minter",
			cfg:  &config{serviceAccount: testServiceAccount, scopes: []string{gcp.ScopeCloudPlatform}},
			key:  key,
		},
		{
			name: "a key file with no usable public key",
			cfg:  &config{serviceAccount: testServiceAccount, scopes: []string{gcp.ScopeCloudPlatform}},
			key:  &keyfile.Key{Public: []byte{0, 1, 2}},
			mint: func() (*gcp.Token, error) { return nil, errMintFailed },
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

			if _, err := tokenFor(testCase.cfg, testCase.key, testCase.mint, io.Discard); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

// TestTokenForCacheFailures covers a cache that cannot be written, which must not cost the token
// just minted, and a cache directory that is not the user's alone, which is refused before
// anything is minted.
//
//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestTokenForCacheFailures(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes through the read-only directory this relies on")
	}

	key := testKey(t)

	testCases := []struct {
		name        string
		prepare     func(t *testing.T, runtimeDir string)
		expectErr   bool
		wantMints   int
		wantWarning bool
	}{
		{
			name: "a token that cannot be cached is still returned, with a warning",
			prepare: func(t *testing.T, runtimeDir string) {
				t.Helper()
				if err := os.Chmod(runtimeDir, 0o500); err != nil {
					t.Fatalf("chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(runtimeDir, 0o700) })
			},
			wantMints:   1,
			wantWarning: true,
		},
		{
			name: "a cache directory open to others is refused before minting",
			prepare: func(t *testing.T, runtimeDir string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(runtimeDir, "tpm-signer"), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.Chmod(filepath.Join(runtimeDir, "tpm-signer"), 0o755); err != nil {
					t.Fatalf("chmod: %v", err)
				}
			},
			expectErr: true,
		},
		{
			name:      "a fresh cache directory is made, and nothing is said",
			prepare:   func(*testing.T, string) {},
			wantMints: 1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			runtimeDir := t.TempDir()
			t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
			testCase.prepare(t, runtimeDir)

			mint, calls := countingMinter()
			var warnings bytes.Buffer
			token, err := tokenFor(
				&config{serviceAccount: testServiceAccount, scopes: []string{gcp.ScopeCloudPlatform}},
				key,
				mint,
				&warnings,
			)
			if *calls != testCase.wantMints {
				t.Errorf("minted %d times, want %d", *calls, testCase.wantMints)
			}
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token == nil || token.AccessToken == "" {
				t.Fatal("no token")
			}
			if got := warnings.Len() != 0; got != testCase.wantWarning {
				t.Errorf("warned = %v (%q), want %v", got, warnings.String(), testCase.wantWarning)
			}
		})
	}
}
