// Command gcp-token mints a Google Cloud access token using a TPM-held key, printing it on
// stdout so it can be fed to Terraform or gcloud:
//
//	export GOOGLE_OAUTH_ACCESS_TOKEN="$(gcp-token -a SERVICE_ACCOUNT)"
//
// No credential file is involved. The only persistent artefact is the TPM key file, which does
// nothing on any other machine.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"

	"github.com/vphpersson/tpm_signer/pkg/gcp"
	"github.com/vphpersson/tpm_signer/pkg/keyfile"
	"github.com/vphpersson/tpm_signer/pkg/pin"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

// refreshMargin is how much life a cached token must have left to be reused, so that a token does
// not expire in the middle of a long apply.
const refreshMargin = 5 * time.Minute

// config is what the command line asks for.
type config struct {
	keyPath        string
	serviceAccount string
	scopes         []string
	devicePath     string
	noCache        bool
	cachedOnly     bool
	exportForm     bool
}

// errNoCachedToken reports that --cached-only found nothing it could print.
var errNoCachedToken = errors.New("no cached token is valid for this request")

// newParser declares the command line, bound to cfg.
func newParser(cfg *config) *argument_parser.Parser {
	noCacheOption := option.NewBoolOption(0, "no-cache", "ignore and do not write the token cache", false, &cfg.noCache)
	cachedOnlyOption := option.NewBoolOption(
		0,
		"cached-only",
		"print a cached token if one is valid, and fail rather than ask for the PIN and mint one",
		false,
		&cfg.cachedOnly,
	)

	return &argument_parser.Parser{
		Description: "Mint a Google Cloud access token with a TPM-held key.",
		ProgramName: "gcp-token",
		ExclusiveGroups: []*argument_parser.ExclusiveGroup{
			{Options: []option.Option{noCacheOption, cachedOnlyOption}},
		},
		Options: []option.Option{
			option.WithDefault(
				option.NewStringOption('f', "key-file", "TPM key file", false, &cfg.keyPath),
				defaultKeyPath(),
			),
			option.NewStringOption('a', "service-account", "service account email to authenticate as", true, &cfg.serviceAccount),
			option.NewStringsOption('s', "scope", "OAuth scope, repeatable", false, &cfg.scopes),
			option.WithDefault(
				option.NewStringOption('D', "device", "TPM device path", false, &cfg.devicePath),
				signer.DefaultDevicePath,
			),
			noCacheOption,
			cachedOnlyOption,
			option.NewBoolOption('e', "export", "print a shell export statement instead of the bare token", false, &cfg.exportForm),
		},
	}
}

// minter mints a fresh token; it is where the PIN is asked for and the TPM is put to work.
type minter func() (*gcp.Token, error)

// tokenFor returns a token for cfg: the cached one when it was minted for the same service
// account, scopes and key and has life left in it, and otherwise one from mint, which is then
// cached. A token that cannot be cached is still returned, with a warning on warnings: by then
// the PIN has been typed and the TPM has signed, and failing would waste both.
func tokenFor(cfg *config, key *keyfile.Key, mint minter, warnings io.Writer) (*gcp.Token, error) {
	if key == nil {
		return nil, nil_error.New("key")
	}
	if mint == nil {
		return nil, nil_error.New("mint")
	}

	cachePath := ""
	var cacheKey *gcp.CacheKey
	if !cfg.noCache {
		publicKey, err := signer.PublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("public key: %w", err)
		}

		cacheKey, err = gcp.NewCacheKey(cfg.serviceAccount, cfg.scopes, publicKey)
		if err != nil {
			return nil, fmt.Errorf("new cache key: %w", err)
		}

		cachePath, err = gcp.CachePath(cacheKey)
		if err != nil {
			return nil, fmt.Errorf("cache path: %w", err)
		}

		cached, err := gcp.LoadToken(cachePath, cacheKey)
		if err != nil {
			return nil, fmt.Errorf("load cached token: %w", err)
		}
		if cached != nil && cached.Valid(refreshMargin) {
			return cached, nil
		}
	}
	// What a caller with no terminal asks for: it could not answer the PIN prompt, so it learns at
	// once that it would have been shown one, rather than after the prompt times out.
	if cfg.cachedOnly {
		return nil, errNoCachedToken
	}

	token, err := mint()
	if err != nil {
		return nil, fmt.Errorf("mint token: %w", err)
	}
	if token == nil {
		return nil, nil_error.New("token")
	}

	if cachePath != "" {
		if err := gcp.StoreToken(cachePath, cacheKey, token); err != nil && warnings != nil {
			_, _ = fmt.Fprintf(warnings, "gcp-token: warning: the token was not cached: %v\n", err)
		}
	}

	return token, nil
}

func run() error {
	cfg := &config{}
	parser := newParser(cfg)
	if err := parser.Validate(); err != nil {
		return fmt.Errorf("parser validate: %w", err)
	}
	parser.ParseOrExit()

	if len(cfg.scopes) == 0 {
		cfg.scopes = []string{gcp.ScopeCloudPlatform}
	}

	keyData, err := os.ReadFile(cfg.keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	key, err := keyfile.Parse(keyData)
	if err != nil {
		return fmt.Errorf("parse key file: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mint := func() (*gcp.Token, error) {
		var pinProvider signer.PINProvider
		if !key.EmptyAuth {
			var scrub func()
			pinProvider, scrub = scrubbing(func() ([]byte, error) {
				return pin.Prompt(ctx, fmt.Sprintf("TPM PIN for %s: ", cfg.serviceAccount), pin.DefaultTimeout)
			})
			defer scrub()
		}

		keySigner, err := signer.New(key, cfg.devicePath, pinProvider)
		if err != nil {
			return nil, fmt.Errorf("new signer: %w", err)
		}

		token, err := (&gcp.Client{}).MintToken(ctx, keySigner, cfg.serviceAccount, cfg.scopes)
		if err != nil {
			return nil, fmt.Errorf("client mint token: %w", err)
		}

		return token, nil
	}

	token, err := tokenFor(cfg, key, mint, os.Stderr)
	if err != nil {
		return fmt.Errorf("token for: %w", err)
	}

	if err := emit(os.Stdout, token.AccessToken, cfg.exportForm); err != nil {
		return fmt.Errorf("emit: %w", err)
	}

	return nil
}

// emit prints the token, bare or as a shell statement. Either way it is checked first: the
// statement is meant for eval, so a token carrying shell syntax would run as code, and the bare
// form is pasted into JSON and environment variables by the scripts that call this.
func emit(writer io.Writer, token string, exportForm bool) error {
	if err := gcp.ValidateAccessToken(token); err != nil {
		return fmt.Errorf("validate access token: %w", err)
	}

	format := "%s\n"
	if exportForm {
		format = "export GOOGLE_OAUTH_ACCESS_TOKEN=%s\n"
	}
	if _, err := fmt.Fprintf(writer, format, token); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

// scrubbing wraps a PIN provider so that every PIN it hands out can be zeroed once signing is
// done, by the function it returns. Sign zeroes only its own copy, and leaves the provider's
// slice to the provider.
func scrubbing(provider signer.PINProvider) (signer.PINProvider, func()) {
	var handedOut [][]byte
	wrapped := func() ([]byte, error) {
		value, err := provider()
		handedOut = append(handedOut, value)
		return value, err
	}
	scrub := func() {
		for _, value := range handedOut {
			clear(value)
		}
	}

	return wrapped, scrub
}

func defaultKeyPath() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "gcp.tpm"
	}

	return filepath.Join(directory, "tpm-signer", "gcp.tpm")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gcp-token: %v\n", err)
		os.Exit(1)
	}
}
