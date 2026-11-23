package gcp

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// CacheKey is what a cached token was minted for. A token is reused only for the same service
// account, the same set of scopes and the same signing key, so that a request for a narrow scope
// is never answered with a cloud-platform token, nor the other way round, and a token minted with
// one key is not handed out after the key file has been replaced by another.
type CacheKey struct {
	ServiceAccount string `json:"service_account"`
	// Scopes are sorted and free of duplicates, so that the order they were asked for in does not
	// matter.
	Scopes []string `json:"scopes"`
	// PublicKey is the hex SHA-256 of the signing key's PKIX SubjectPublicKeyInfo.
	PublicKey string `json:"public_key"`
}

// NewCacheKey builds the key a token for these scopes, signed by this public key, is cached under.
func NewCacheKey(serviceAccount string, scopes []string, publicKey crypto.PublicKey) (*CacheKey, error) {
	if serviceAccount == "" {
		return nil, empty_error.New("service account")
	}
	if len(scopes) == 0 {
		return nil, empty_error.New("scopes")
	}
	if publicKey == nil {
		return nil, nil_error.New("public key")
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("x509 marshal pkix public key: %w", err),
			fmt.Sprintf("%T", publicKey),
		)
	}
	sum := sha256.Sum256(der)

	sorted := slices.Clone(scopes)
	slices.Sort(sorted)

	return &CacheKey{
		ServiceAccount: serviceAccount,
		Scopes:         slices.Compact(sorted),
		PublicKey:      hex.EncodeToString(sum[:]),
	}, nil
}

func (key *CacheKey) validate() error {
	if key == nil {
		return nil_error.New("cache key")
	}
	if key.ServiceAccount == "" {
		return empty_error.New("service account")
	}
	if len(key.Scopes) == 0 {
		return empty_error.New("scopes")
	}
	if key.PublicKey == "" {
		return empty_error.New("public key")
	}

	return nil
}

// cacheEntry is the cache file: the token, and what it was minted for.
type cacheEntry struct {
	Key   *CacheKey `json:"key"`
	Token *Token    `json:"token"`
}

// CachePath locates the cache file for a cache key.
//
// It lives under XDG_RUNTIME_DIR, which is tmpfs and is cleared when the session ends. That is
// deliberate: the access token is a bearer credential, and the point of the exercise is to keep
// bearer credentials off persistent storage.
func CachePath(key *CacheKey) (string, error) {
	if err := key.validate(); err != nil {
		return "", fmt.Errorf("validate cache key: %w", err)
	}

	directory := os.Getenv("XDG_RUNTIME_DIR")
	if directory == "" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: XDG_RUNTIME_DIR is unset, refusing to cache a token on disk", altshiftErrors.ErrValidationError),
		)
	}

	// The struct marshals its fields in declaration order, so the same key always names the same
	// file.
	canonical, err := json.Marshal(key)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("marshal cache key: %w", err))
	}
	sum := sha256.Sum256(canonical)

	return filepath.Join(directory, "tpm-signer", hex.EncodeToString(sum[:16])+".json"), nil
}

// LoadToken reads a cached token. A missing or unreadable cache is not an error; it yields a nil
// token, and the caller mints a fresh one. So does a cache file written for anything other than
// the key asked for.
func LoadToken(path string, key *CacheKey) (*Token, error) {
	if path == "" {
		return nil, empty_error.New("path")
	}
	if err := key.validate(); err != nil {
		return nil, fmt.Errorf("validate cache key: %w", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // The path is CachePath's.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read cache: %w", err), path)
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, nil
	}
	if entry.Token == nil || !entry.Key.equal(key) {
		return nil, nil
	}

	return entry.Token, nil
}

func (key *CacheKey) equal(other *CacheKey) bool {
	if key == nil || other == nil {
		return false
	}

	return key.ServiceAccount == other.ServiceAccount &&
		key.PublicKey == other.PublicKey &&
		slices.Equal(key.Scopes, other.Scopes)
}

// StoreToken writes a token to the cache, with the key it was minted for, readable only by its
// owner.
func StoreToken(path string, key *CacheKey, token *Token) error {
	if path == "" {
		return empty_error.New("path")
	}
	if err := key.validate(); err != nil {
		return fmt.Errorf("validate cache key: %w", err)
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
	data, err := json.Marshal(&cacheEntry{Key: key, Token: token}) //nolint:gosec // G117: see above.
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("marshal cache entry: %w", err))
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
