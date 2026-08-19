package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// CachePath locates the cache file for a service account.
//
// It lives under XDG_RUNTIME_DIR, which is tmpfs and is cleared when the session ends. That is
// deliberate: the access token is a bearer credential, and the point of the exercise is to keep
// bearer credentials off persistent storage.
func CachePath(serviceAccount string) (string, error) {
	if serviceAccount == "" {
		return "", empty_error.New("service account")
	}

	directory := os.Getenv("XDG_RUNTIME_DIR")
	if directory == "" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: XDG_RUNTIME_DIR is unset, refusing to cache a token on disk", altshiftErrors.ErrValidationError),
		)
	}

	sum := sha256.Sum256([]byte(serviceAccount))

	return filepath.Join(directory, "tpm-signer", hex.EncodeToString(sum[:8])+".json"), nil
}

// LoadToken reads a cached token. A missing or unreadable cache is not an error; it yields a nil
// token, and the caller mints a fresh one.
func LoadToken(path string) (*Token, error) {
	if path == "" {
		return nil, empty_error.New("path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read cache: %w", err), path)
	}

	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, nil
	}

	return &token, nil
}

// StoreToken writes a token to the cache, readable only by its owner.
func StoreToken(path string, token *Token) error {
	if path == "" {
		return empty_error.New("path")
	}
	if token == nil {
		return nil_error.New("token")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("mkdir cache directory: %w", err), filepath.Dir(path))
	}

	// The access token really is a secret. Writing it here is the deliberate trade: it goes to
	// tmpfs, mode 0600, and expires within the hour, which is what lets Terraform run repeatedly
	// without re-prompting for the PIN.
	data, err := json.Marshal(token) //nolint:gosec // G117: see above.
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("marshal token: %w", err))
	}

	// Written to a temporary file and renamed so a concurrent reader never sees a partial token.
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("write cache: %w", err), temporary)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return altshiftErrors.NewWithTrace(fmt.Errorf("rename cache: %w", err), temporary, path)
	}

	return nil
}
