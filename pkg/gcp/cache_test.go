package gcp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestCachePath(t *testing.T) {
	testCases := []struct {
		name           string
		serviceAccount string
		runtimeDir     string
		expectErr      bool
	}{
		{name: "valid", serviceAccount: "robot@project.iam.gserviceaccount.com", runtimeDir: "/run/user/1000"},
		{name: "empty service account", runtimeDir: "/run/user/1000", expectErr: true},
		{name: "no runtime dir", serviceAccount: "robot@project.iam.gserviceaccount.com", expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) { //nolint:paralleltest // t.Setenv, as above.
			t.Setenv("XDG_RUNTIME_DIR", testCase.runtimeDir)

			path, err := CachePath(testCase.serviceAccount)
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

// TestCachePathIsStableAndDistinct guards the property the cache depends on: one file per service
// account, and the same file every time.
//
//nolint:paralleltest // t.Setenv mutates process state and cannot run alongside other tests.
func TestCachePathIsStableAndDistinct(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	first, err := CachePath("a@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	again, err := CachePath("a@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	other, err := CachePath("b@project.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if first != again {
		t.Errorf("path is not stable: %q then %q", first, again)
	}
	if first == other {
		t.Errorf("distinct service accounts share a cache file: %q", first)
	}
}

func TestStoreAndLoadToken(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()

	testCases := []struct {
		name      string
		token     *Token
		expectErr bool
	}{
		{name: "round trip", token: &Token{AccessToken: "ya29.x", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour).Round(time.Second)}},
		{name: "nil token", token: nil, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(directory, testCase.name+".json")

			err := StoreToken(path, testCase.token)
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

			loaded, err := LoadToken(path)
			if err != nil {
				t.Fatalf("load: %v", err)
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

	directory := t.TempDir()

	corrupt := filepath.Join(directory, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	testCases := []struct {
		name string
		path string
	}{
		{name: "missing file yields no token", path: filepath.Join(directory, "absent.json")},
		{name: "corrupt file yields no token", path: corrupt},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := LoadToken(testCase.path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token != nil {
				t.Errorf("expected no token, got %+v", token)
			}
		})
	}
}
