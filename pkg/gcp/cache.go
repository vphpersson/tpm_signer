package gcp

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"

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

// LoadToken reads a cached token. A missing or corrupt cache file is not an error; it yields a
// nil token, and the caller mints a fresh one. So does a cache file written for anything other
// than the key asked for, and one that is a link, or open to anyone else. A cache directory that
// is not this user's alone is an error, since nothing written there would be safe either.
func LoadToken(path string, key *CacheKey) (*Token, error) {
	if path == "" {
		return nil, empty_error.New("path")
	}
	if err := key.validate(); err != nil {
		return nil, fmt.Errorf("validate cache key: %w", err)
	}

	switch err := checkCacheDirectory(filepath.Dir(path)); {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("check cache directory: %w", err)
	}

	data, err := readCacheFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cache file: %w", err)
	}
	if data == nil {
		return nil, nil
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, nil
	}
	if entry.Token == nil || !entry.Key.equal(key) || ValidateAccessToken(entry.Token.AccessToken) != nil {
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

	directory := filepath.Dir(path)
	if err := ensureCacheDirectory(directory); err != nil {
		return fmt.Errorf("ensure cache directory: %w", err)
	}

	// The access token really is a secret. Writing it here is the deliberate trade: it goes to
	// tmpfs, mode 0600, and expires within the hour, which is what lets Terraform run repeatedly
	// without re-prompting for the PIN.
	data, err := json.Marshal(&cacheEntry{Key: key, Token: token}) //nolint:gosec // G117: see above.
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("marshal cache entry: %w", err))
	}

	// Written to a temporary file and renamed so a concurrent reader never sees a partial token.
	// CreateTemp opens with O_EXCL and mode 0600 under a name of its own choosing, so it never
	// follows a link left in its way, and two processes minting at once each write their own file;
	// the second rename replaces the first, and both succeed.
	file, err := os.CreateTemp(directory, filepath.Base(path)+".*.tmp")
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("create temp: %w", err), directory)
	}
	temporary := file.Name()

	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = os.Remove(temporary)
		return altshiftErrors.NewWithTrace(fmt.Errorf("write cache: %w", err), temporary)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return altshiftErrors.NewWithTrace(fmt.Errorf("rename cache: %w", err), temporary, path)
	}

	return nil
}

// maxCacheFileSize bounds what is read back; a cache entry is a few hundred bytes.
const maxCacheFileSize = 64 << 10

// ensureCacheDirectory creates the cache directory if it is not there, and then holds it to
// checkCacheDirectory's rules either way.
func ensureCacheDirectory(directory string) error {
	err := os.Mkdir(directory, 0o700)
	switch {
	case err == nil:
		// The umask can only narrow Mkdir's mode, but narrower than 0700 is no use either.
		if err := os.Chmod(directory, 0o700); err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("chmod: %w", err), directory)
		}
	case errors.Is(err, fs.ErrExist):
	default:
		return altshiftErrors.NewWithTrace(fmt.Errorf("mkdir: %w", err), directory)
	}

	return checkCacheDirectory(directory)
}

// checkCacheDirectory refuses a cache directory that is not this user's alone: a directory, not a
// link to one, owned by this uid, with mode 0700. A token put there by anyone else would be handed
// out as this user's, and one written where others can look is theirs to lift. The error wraps
// fs.ErrNotExist when there is no directory at all.
func checkCacheDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("lstat: %w", err), directory)
	}
	if !info.IsDir() {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: cache directory is not a directory", altshiftErrors.ErrVerificationError),
			directory, info.Mode().String(),
		)
	}

	if !ownedByCurrentUser(info) {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: cache directory belongs to another user", altshiftErrors.ErrVerificationError),
			directory, os.Getuid(),
		)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: cache directory mode is %#o, want 0700", altshiftErrors.ErrVerificationError, mode),
			directory,
		)
	}

	return nil
}

// ownedByCurrentUser reports whether the file belongs to this process's real uid. Both sides are
// widened to int64, which holds a uint32 uid and an int alike.
func ownedByCurrentUser(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return false
	}

	return int64(stat.Uid) == int64(os.Getuid())
}

// readCacheFile reads a cache file without following a link, and yields nil data for anything
// that is not a regular file of this user's, closed to everyone else: such a file is not used,
// and the next StoreToken replaces it.
func readCacheFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // The path is CachePath's.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ELOOP) {
			return nil, nil
		}
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("open: %w", err), path)
	}
	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("stat: %w", err), path)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) {
		return nil, nil
	}

	data, err := io.ReadAll(io.LimitReader(file, maxCacheFileSize))
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read: %w", err), path)
	}

	return data, nil
}
