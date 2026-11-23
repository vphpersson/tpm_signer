package gcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
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

// TestCacheDirectory holds the cache directory to being the user's alone, on the way in and the
// way out.
func TestCacheDirectory(t *testing.T) {
	t.Parallel()

	key := testCacheKey(t, []string{ScopeCloudPlatform}, testPublicKey(t))
	token := &Token{AccessToken: "ya29.x", Expiry: time.Now().Add(time.Hour)}

	testCases := []struct {
		name string
		// prepare lays out the runtime directory and returns the cache directory to use.
		prepare        func(t *testing.T, runtimeDir string) string
		expectStoreErr bool
		expectLoadErr  bool
	}{
		{
			name:    "a missing directory is made, mode 0700",
			prepare: func(_ *testing.T, runtimeDir string) string { return filepath.Join(runtimeDir, "tpm-signer") },
		},
		{
			name: "an existing directory of the user's, mode 0700",
			prepare: func(t *testing.T, runtimeDir string) string {
				t.Helper()
				return mkdir(t, filepath.Join(runtimeDir, "tpm-signer"), 0o700)
			},
		},
		{
			name: "a directory others can read is refused",
			prepare: func(t *testing.T, runtimeDir string) string {
				t.Helper()
				return mkdir(t, filepath.Join(runtimeDir, "tpm-signer"), 0o755)
			},
			expectStoreErr: true,
			expectLoadErr:  true,
		},
		{
			name: "a directory the group can write is refused",
			prepare: func(t *testing.T, runtimeDir string) string {
				t.Helper()
				return mkdir(t, filepath.Join(runtimeDir, "tpm-signer"), 0o770)
			},
			expectStoreErr: true,
			expectLoadErr:  true,
		},
		{
			name: "a link to a directory of the user's is refused",
			prepare: func(t *testing.T, runtimeDir string) string {
				t.Helper()
				target := mkdir(t, filepath.Join(runtimeDir, "elsewhere"), 0o700)
				link := filepath.Join(runtimeDir, "tpm-signer")
				if err := os.Symlink(target, link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return link
			},
			expectStoreErr: true,
			expectLoadErr:  true,
		},
		{
			name: "a file in the directory's place is refused",
			prepare: func(t *testing.T, runtimeDir string) string {
				t.Helper()
				path := filepath.Join(runtimeDir, "tpm-signer")
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				return path
			},
			expectStoreErr: true,
			expectLoadErr:  true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			directory := testCase.prepare(t, t.TempDir())
			path := filepath.Join(directory, "token.json")

			err := StoreToken(path, key, token)
			if testCase.expectStoreErr {
				if err == nil {
					t.Error("store: expected an error, got none")
				} else if !errors.Is(err, altshiftErrors.ErrVerificationError) {
					t.Errorf("store: error %v is not a verification error", err)
				}
			} else if err != nil {
				t.Fatalf("store: unexpected error: %v", err)
			}

			loaded, err := LoadToken(path, key)
			if testCase.expectLoadErr {
				if err == nil {
					t.Error("load: expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("load: unexpected error: %v", err)
			}
			if loaded == nil || loaded.AccessToken != token.AccessToken {
				t.Errorf("loaded %+v, want the stored token", loaded)
			}

			info, err := os.Lstat(directory)
			if err != nil {
				t.Fatalf("lstat: %v", err)
			}
			if mode := info.Mode().Perm(); !info.IsDir() || mode != 0o700 {
				t.Errorf("cache directory mode = %v, want a directory with mode 0700", info.Mode())
			}
		})
	}
}

func mkdir(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()

	if err := os.Mkdir(path, mode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Mkdir's mode passes through the umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	return path
}

// TestCacheFileIsNotFollowed covers what might be lying in the cache directory under the names
// the cache uses: a link at the cache file is neither read nor written through, a link at the
// temporary name an older gcp-token used is never written through, and a cache file others can
// read is not used.
func TestCacheFileIsNotFollowed(t *testing.T) {
	t.Parallel()

	key := testCacheKey(t, []string{ScopeCloudPlatform}, testPublicKey(t))
	token := &Token{AccessToken: "ya29.fresh", Expiry: time.Now().Add(time.Hour)}

	// planted is a valid cache file somewhere else, holding someone else's token.
	planted := func(t *testing.T, path string, mode os.FileMode) {
		t.Helper()
		if err := StoreToken(path, key, &Token{AccessToken: "ya29.planted", Expiry: time.Now().Add(time.Hour)}); err != nil {
			t.Fatalf("store planted token: %v", err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
	}

	testCases := []struct {
		name    string
		prepare func(t *testing.T, path string, victim string)
	}{
		{
			name: "a link at the cache file",
			prepare: func(t *testing.T, path string, victim string) {
				t.Helper()
				planted(t, victim, 0o600)
				if err := os.Symlink(victim, path); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "a link at the old fixed temporary name",
			prepare: func(t *testing.T, path string, victim string) {
				t.Helper()
				planted(t, victim, 0o600)
				if err := os.Symlink(victim, path+".tmp"); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "a cache file others can read",
			prepare: func(t *testing.T, path string, _ string) {
				t.Helper()
				planted(t, path, 0o644)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			directory := mkdir(t, filepath.Join(t.TempDir(), "tpm-signer"), 0o700)
			victimDirectory := mkdir(t, filepath.Join(t.TempDir(), "victim"), 0o700)
			path := filepath.Join(directory, "token.json")
			victim := filepath.Join(victimDirectory, "victim.json")
			testCase.prepare(t, path, victim)

			before, _ := os.ReadFile(victim)

			loaded, err := LoadToken(path, key)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if loaded != nil {
				t.Errorf("loaded %q from a file that should not have been used", loaded.AccessToken)
			}

			if err := StoreToken(path, key, token); err != nil {
				t.Fatalf("store: %v", err)
			}

			after, _ := os.ReadFile(victim)
			if string(before) != string(after) {
				t.Error("storing wrote through a link to a file outside the cache")
			}

			loaded, err = LoadToken(path, key)
			if err != nil {
				t.Fatalf("load after store: %v", err)
			}
			if loaded == nil || loaded.AccessToken != token.AccessToken {
				t.Errorf("after storing, loaded %+v, want the fresh token", loaded)
			}
		})
	}
}

// TestStoreTokenConcurrently is two cold mints finishing at once, many times over: every store
// must succeed, since a failure there is a PIN typed for nothing, and the file left behind must
// be one of them, whole.
func TestStoreTokenConcurrently(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		writers int
		rounds  int
	}{
		{name: "two writers", writers: 2, rounds: 200},
		{name: "many writers", writers: 16, rounds: 20},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key := testCacheKey(t, []string{ScopeCloudPlatform}, testPublicKey(t))

			for round := range testCase.rounds {
				path := filepath.Join(t.TempDir(), "tpm-signer", "token.json")

				var waitGroup sync.WaitGroup
				failures := make(chan error, testCase.writers)
				for writer := range testCase.writers {
					waitGroup.Go(func() {
						token := &Token{AccessToken: fmt.Sprintf("ya29.writer-%d", writer), Expiry: time.Now().Add(time.Hour)}
						if err := StoreToken(path, key, token); err != nil {
							failures <- err
						}
					})
				}
				waitGroup.Wait()
				close(failures)

				for err := range failures {
					t.Fatalf("round %d: a concurrent store failed: %v", round, err)
				}

				loaded, err := LoadToken(path, key)
				if err != nil || loaded == nil {
					t.Fatalf("round %d: load = %+v, %v", round, loaded, err)
				}

				leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp"))
				if err != nil {
					t.Fatalf("glob: %v", err)
				}
				if len(leftovers) != 0 {
					t.Fatalf("round %d: temporary files left behind: %v", round, leftovers)
				}
			}
		})
	}
}

func TestCheckCacheDirectoryMissing(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		path string
	}{
		{name: "a directory that is not there wraps fs.ErrNotExist", path: filepath.Join(t.TempDir(), "absent")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := checkCacheDirectory(testCase.path); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("error = %v, want one wrapping fs.ErrNotExist", err)
			}
		})
	}
}
