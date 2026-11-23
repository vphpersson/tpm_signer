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
		given      string
		exportForm bool
		expectErr  bool
		want       string
	}{
		{name: "bare token", given: "ya29.test", want: "ya29.test\n"},
		{
			name:       "export statement",
			given:      "ya29.test",
			exportForm: true,
			want:       "export GOOGLE_OAUTH_ACCESS_TOKEN=ya29.test\n",
		},
		{
			name:       "every character of the alphabet",
			given:      "access.AZaz09._~+/=-",
			exportForm: true,
			want:       "export GOOGLE_OAUTH_ACCESS_TOKEN=access.AZaz09._~+/=-\n",
		},
		{name: "a command after the assignment", given: "access;touch${IFS}pwned", exportForm: true, expectErr: true},
		{name: "a command substitution", given: "$(touch pwned)", exportForm: true, expectErr: true},
		{name: "a backtick substitution", given: "`touch pwned`", exportForm: true, expectErr: true},
		{name: "a second line", given: "access\ntouch pwned", exportForm: true, expectErr: true},
		{name: "a space", given: "access touch", exportForm: true, expectErr: true},
		{name: "a quote, bare, would break the docker helper's JSON", given: `access"}`, expectErr: true},
		{name: "a non-ascii byte", given: "access\u00e9", expectErr: true},
		{name: "empty", given: "", expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer
			err := emit(&output, testCase.given, testCase.exportForm)
			if testCase.expectErr {
				if err == nil {
					t.Error("expected an error, got none")
				}
				if output.Len() != 0 {
					t.Errorf("printed %q for a token that was refused", output.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

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
		// As a current tpm-keygen records it; nothing here checks it against a TPM.
		ParentName: []byte{0x00, 0x0b, 0x01, 0x02},
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

// cachedToken is a token left in the cache by an earlier run, with lifetime left in it.
func cachedToken(lifetime time.Duration) *gcp.Token {
	return &gcp.Token{AccessToken: "ya29.cached", Expiry: time.Now().Add(lifetime)} //nolint:gosec // G101: a test fixture, not a credential.
}

//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestTokenForCachedOnly(t *testing.T) {
	key := testKey(t)
	broad := []string{gcp.ScopeCloudPlatform}

	testCases := []struct {
		name string
		// cached is what a run with a terminal left in the cache beforehand, if anything.
		cached    *gcp.Token
		scopes    []string
		expectErr bool
	}{
		{name: "nothing cached", scopes: broad, expectErr: true},
		{
			name:   "a valid token is printed",
			cached: cachedToken(time.Hour),
			scopes: broad,
		},
		{
			name:      "a token about to expire is not",
			cached:    cachedToken(time.Minute),
			scopes:    broad,
			expectErr: true,
		},
		{
			name:      "a token for other scopes is not",
			cached:    cachedToken(time.Hour),
			scopes:    []string{testReadOnlyScope},
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

			if testCase.cached != nil {
				seed := func() (*gcp.Token, error) { return testCase.cached, nil }
				if _, err := tokenFor(&config{serviceAccount: testServiceAccount, scopes: broad}, key, seed, io.Discard); err != nil {
					t.Fatalf("seed the cache: %v", err)
				}
			}

			mint, calls := countingMinter()
			token, err := tokenFor(
				&config{serviceAccount: testServiceAccount, scopes: testCase.scopes, cachedOnly: true},
				key,
				mint,
				io.Discard,
			)
			if *calls != 0 {
				t.Errorf("minted %d times, want none: --cached-only must never ask for the PIN", *calls)
			}
			if testCase.expectErr {
				if !errors.Is(err, errNoCachedToken) {
					t.Errorf("error = %v, want errNoCachedToken", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token.AccessToken != testCase.cached.AccessToken {
				t.Errorf("token = %q, want the cached %q", token.AccessToken, testCase.cached.AccessToken)
			}
		})
	}
}

func TestParseArguments(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		arguments      []string
		expectErr      bool
		wantCachedOnly bool
		wantNoCache    bool
		wantScopes     []string
	}{
		{name: "a service account alone", arguments: []string{"-a", testServiceAccount}},
		{name: "cached only", arguments: []string{"-a", testServiceAccount, "--cached-only"}, wantCachedOnly: true},
		{name: "no cache", arguments: []string{"-a", testServiceAccount, "--no-cache"}, wantNoCache: true},
		{
			name:       "repeated scopes",
			arguments:  []string{"-a", testServiceAccount, "-s", gcp.ScopeCloudPlatform, "-s", testReadOnlyScope},
			wantScopes: []string{gcp.ScopeCloudPlatform, testReadOnlyScope},
		},
		{name: "cached only and no cache rule each other out", arguments: []string{"-a", testServiceAccount, "--cached-only", "--no-cache"}, expectErr: true},
		{name: "no service account", arguments: []string{"--cached-only"}, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config{}
			parser := newParser(cfg)
			if err := parser.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}

			err := parser.ParseArgs(testCase.arguments)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.cachedOnly != testCase.wantCachedOnly {
				t.Errorf("cached only = %v, want %v", cfg.cachedOnly, testCase.wantCachedOnly)
			}
			if cfg.noCache != testCase.wantNoCache {
				t.Errorf("no cache = %v, want %v", cfg.noCache, testCase.wantNoCache)
			}
			if len(cfg.scopes) != len(testCase.wantScopes) {
				t.Errorf("scopes = %v, want %v", cfg.scopes, testCase.wantScopes)
			}
			if cfg.serviceAccount != testServiceAccount {
				t.Errorf("service account = %q, want %q", cfg.serviceAccount, testServiceAccount)
			}
		})
	}
}

//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestTokenForWarnsOfAnUnrecordedParent(t *testing.T) {
	legacy := func() *keyfile.Key {
		key := testKey(t)
		key.ParentName = nil
		return key
	}
	noPIN := legacy()
	noPIN.EmptyAuth = true

	testCases := []struct {
		name        string
		key         *keyfile.Key
		cached      bool
		wantWarning bool
	}{
		{name: "a pin key from before the name was recorded", key: legacy(), wantWarning: true},
		{name: "a pin key with the name recorded", key: testKey(t)},
		{name: "a key without a pin has nothing to lose to an impostor", key: noPIN},
		{name: "a cached token does not use the key", key: legacy(), cached: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			cfg := &config{serviceAccount: testServiceAccount, scopes: []string{gcp.ScopeCloudPlatform}}

			mint, _ := countingMinter()
			if testCase.cached {
				if _, err := tokenFor(cfg, testCase.key, mint, io.Discard); err != nil {
					t.Fatalf("seed the cache: %v", err)
				}
			}

			var warnings bytes.Buffer
			if _, err := tokenFor(cfg, testCase.key, mint, &warnings); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := strings.Contains(warnings.String(), unrecordedParentWarning); got != testCase.wantWarning {
				t.Errorf("warned = %v (%q), want %v", got, warnings.String(), testCase.wantWarning)
			}
		})
	}
}
