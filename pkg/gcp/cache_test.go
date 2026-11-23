package gcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const (
	testServiceAccount = "robot@project.iam.gserviceaccount.com"
	testReadOnlyScope  = "https://www.googleapis.com/auth/devstorage.read_only"
)

// testPublicKey is a software key's public half; the cache only ever hashes it.
func testPublicKey(t *testing.T) crypto.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key.Public()
}

func testCacheKey(t *testing.T, scopes []string, publicKey crypto.PublicKey) *CacheKey {
	t.Helper()

	key, err := NewCacheKey(testServiceAccount, scopes, publicKey)
	if err != nil {
		t.Fatalf("new cache key: %v", err)
	}

	return key
}

func TestNewCacheKey(t *testing.T) {
	t.Parallel()

	publicKey := testPublicKey(t)

	testCases := []struct {
		name           string
		serviceAccount string
		scopes         []string
		publicKey      crypto.PublicKey
		expectErr      bool
		wantScopes     []string
	}{
		{
			name:           "scopes are sorted",
			serviceAccount: testServiceAccount,
			scopes:         []string{testReadOnlyScope, ScopeCloudPlatform},
			publicKey:      publicKey,
			wantScopes:     []string{ScopeCloudPlatform, testReadOnlyScope},
		},
		{
			name:           "duplicate scopes collapse",
			serviceAccount: testServiceAccount,
			scopes:         []string{ScopeCloudPlatform, ScopeCloudPlatform},
			publicKey:      publicKey,
			wantScopes:     []string{ScopeCloudPlatform},
		},
		{name: "no service account", scopes: []string{ScopeCloudPlatform}, publicKey: publicKey, expectErr: true},
		{name: "no scopes", serviceAccount: testServiceAccount, publicKey: publicKey, expectErr: true},
		{name: "no public key", serviceAccount: testServiceAccount, scopes: []string{ScopeCloudPlatform}, expectErr: true},
		{
			name:           "a key that is not a public key",
			serviceAccount: testServiceAccount,
			scopes:         []string{ScopeCloudPlatform},
			publicKey:      "not a key",
			expectErr:      true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			scopes := slices.Clone(testCase.scopes)
			key, err := NewCacheKey(testCase.serviceAccount, scopes, testCase.publicKey)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(key.Scopes, testCase.wantScopes) {
				t.Errorf("scopes = %v, want %v", key.Scopes, testCase.wantScopes)
			}
			if !slices.Equal(scopes, testCase.scopes) {
				t.Errorf("the caller's scopes were reordered to %v", scopes)
			}
			if len(key.PublicKey) != 64 {
				t.Errorf("public key hash %q is not a hex SHA-256", key.PublicKey)
			}
		})
	}
}

//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestCachePath(t *testing.T) {
	key := testCacheKey(t, []string{ScopeCloudPlatform}, testPublicKey(t))

	testCases := []struct {
		name       string
		key        *CacheKey
		runtimeDir string
		expectErr  bool
	}{
		{name: "valid", key: key, runtimeDir: "/run/user/1000"},
		{name: "nil key", runtimeDir: "/run/user/1000", expectErr: true},
		{name: "empty key", key: &CacheKey{}, runtimeDir: "/run/user/1000", expectErr: true},
		{name: "no runtime dir", key: key, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			t.Setenv("XDG_RUNTIME_DIR", testCase.runtimeDir)

			path, err := CachePath(testCase.key)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filepath.Dir(filepath.Dir(path)) != testCase.runtimeDir {
				t.Errorf("path %q is not under %q", path, testCase.runtimeDir)
			}
		})
	}
}

// TestCachePathSeparatesScopesAndKeys guards the property the cache depends on: one file per
// service account, set of scopes and signing key, and the same file every time.
//
//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestCachePathSeparatesScopesAndKeys(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	publicKey := testPublicKey(t)
	otherPublicKey := testPublicKey(t)
	broad := []string{ScopeCloudPlatform}
	both := []string{ScopeCloudPlatform, testReadOnlyScope}

	other, err := NewCacheKey("other@project.iam.gserviceaccount.com", broad, publicKey)
	if err != nil {
		t.Fatalf("new cache key: %v", err)
	}

	testCases := []struct {
		name      string
		first     *CacheKey
		second    *CacheKey
		wantEqual bool
	}{
		{name: "the same key twice", first: testCacheKey(t, broad, publicKey), second: testCacheKey(t, broad, publicKey), wantEqual: true},
		{
			name:      "scopes in another order",
			first:     testCacheKey(t, both, publicKey),
			second:    testCacheKey(t, []string{testReadOnlyScope, ScopeCloudPlatform}, publicKey),
			wantEqual: true,
		},
		{name: "a narrower scope", first: testCacheKey(t, broad, publicKey), second: testCacheKey(t, []string{testReadOnlyScope}, publicKey)},
		{name: "an extra scope", first: testCacheKey(t, broad, publicKey), second: testCacheKey(t, both, publicKey)},
		{name: "another signing key", first: testCacheKey(t, broad, publicKey), second: testCacheKey(t, broad, otherPublicKey)},
		{name: "another service account", first: testCacheKey(t, broad, publicKey), second: other},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			first, err := CachePath(testCase.first)
			if err != nil {
				t.Fatalf("cache path: %v", err)
			}
			second, err := CachePath(testCase.second)
			if err != nil {
				t.Fatalf("cache path: %v", err)
			}
			if (first == second) != testCase.wantEqual {
				t.Errorf("paths %q and %q: equal = %v, want %v", first, second, first == second, testCase.wantEqual)
			}
		})
	}
}

func TestStoreAndLoadToken(t *testing.T) {
	t.Parallel()

	publicKey := testPublicKey(t)
	key := testCacheKey(t, []string{ScopeCloudPlatform}, publicKey)
	token := &Token{AccessToken: "ya29.x", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour).Round(time.Second)}

	testCases := []struct {
		name      string
		storeKey  *CacheKey
		loadKey   *CacheKey
		token     *Token
		expectErr bool
		wantToken bool
	}{
		{name: "round trip", storeKey: key, loadKey: key, token: token, wantToken: true},
		{
			// The file names differ too, so this takes a hash collision or a file put in place by
			// hand; the token must still not be handed out for a key it was not minted for.
			name:     "a token stored for a broad scope is not loaded for a narrow one",
			storeKey: key,
			loadKey:  testCacheKey(t, []string{testReadOnlyScope}, publicKey),
			token:    token,
		},
		{
			name:     "a token stored for one key is not loaded for another",
			storeKey: key,
			loadKey:  testCacheKey(t, []string{ScopeCloudPlatform}, testPublicKey(t)),
			token:    token,
		},
		{name: "nil token", storeKey: key, loadKey: key, token: nil, expectErr: true},
		{name: "nil key", loadKey: key, token: token, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "tpm-signer", "token.json")

			err := StoreToken(path, testCase.storeKey, testCase.token)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("cache mode = %o, want 600", mode)
			}

			loaded, err := LoadToken(path, testCase.loadKey)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if !testCase.wantToken {
				if loaded != nil {
					t.Errorf("loaded %+v, want no token", loaded)
				}
				return
			}
			if loaded == nil {
				t.Fatal("loaded no token")
			}
			if loaded.AccessToken != testCase.token.AccessToken {
				t.Errorf("access token = %q, want %q", loaded.AccessToken, testCase.token.AccessToken)
			}
			if !loaded.Expiry.Equal(testCase.token.Expiry) {
				t.Errorf("expiry = %v, want %v", loaded.Expiry, testCase.token.Expiry)
			}
		})
	}
}

func TestLoadTokenMissingOrCorrupt(t *testing.T) {
	t.Parallel()

	key := testCacheKey(t, []string{ScopeCloudPlatform}, testPublicKey(t))
	directory := t.TempDir()

	write := func(name string, content string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return path
	}

	testCases := []struct {
		name string
		path string
	}{
		{name: "missing file yields no token", path: filepath.Join(directory, "absent.json")},
		{name: "corrupt file yields no token", path: write("corrupt.json", "not json")},
		{
			// What an older gcp-token wrote: a bare token, with nothing to say what it was minted for.
			name: "a file with no key yields no token",
			path: write("legacy.json", `{"access_token":"ya29.x","expiry":"2099-01-01T00:00:00Z"}`),
		},
		{name: "a file with a key and no token yields no token", path: write("keyless.json", `{"key":{"service_account":"x"}}`)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := LoadToken(testCase.path, key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != nil {
				t.Errorf("expected no token, got %+v", token)
			}
		})
	}
}
