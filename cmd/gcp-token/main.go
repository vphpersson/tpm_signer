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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"

	"github.com/vphpersson/tpm_signer/pkg/gcp"
	"github.com/vphpersson/tpm_signer/pkg/keyfile"
	"github.com/vphpersson/tpm_signer/pkg/pin"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

// refreshMargin is how much life a cached token must have left to be reused, so that a token does
// not expire in the middle of a long apply.
const refreshMargin = 5 * time.Minute

func run() error {
	var keyPath string
	var serviceAccount string
	var scopes []string
	var devicePath string
	var noCache bool
	var exportForm bool

	parser := &argument_parser.Parser{
		Description: "Mint a Google Cloud access token with a TPM-held key.",
		ProgramName: "gcp-token",
		Options: []option.Option{
			option.WithDefault(
				option.NewStringOption('f', "key-file", "TPM key file", false, &keyPath),
				defaultKeyPath(),
			),
			option.NewStringOption('a', "service-account", "service account email to authenticate as", true, &serviceAccount),
			option.NewStringsOption('s', "scope", "OAuth scope, repeatable", false, &scopes),
			option.WithDefault(
				option.NewStringOption('D', "device", "TPM device path", false, &devicePath),
				signer.DefaultDevicePath,
			),
			option.NewBoolOption(0, "no-cache", "ignore and do not write the token cache", false, &noCache),
			option.NewBoolOption('e', "export", "print a shell export statement instead of the bare token", false, &exportForm),
		},
	}
	if err := parser.Validate(); err != nil {
		return fmt.Errorf("parser validate: %w", err)
	}
	parser.ParseOrExit()

	if len(scopes) == 0 {
		scopes = []string{gcp.ScopeCloudPlatform}
	}

	cachePath := ""
	if !noCache {
		var err error
		cachePath, err = gcp.CachePath(serviceAccount)
		if err != nil {
			return fmt.Errorf("cache path: %w", err)
		}

		cached, err := gcp.LoadToken(cachePath)
		if err != nil {
			return fmt.Errorf("load cached token: %w", err)
		}
		if cached != nil && cached.Valid(refreshMargin) {
			emit(cached.AccessToken, exportForm)
			return nil
		}
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	key, err := keyfile.Parse(keyData)
	if err != nil {
		return fmt.Errorf("parse key file: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var pinProvider signer.PINProvider
	if !key.EmptyAuth {
		pinProvider = func() ([]byte, error) {
			return pin.Prompt(ctx, fmt.Sprintf("TPM PIN for %s: ", serviceAccount), pin.DefaultTimeout)
		}
	}

	keySigner, err := signer.New(key, devicePath, pinProvider)
	if err != nil {
		return fmt.Errorf("new signer: %w", err)
	}

	token, err := (&gcp.Client{}).MintToken(ctx, keySigner, serviceAccount, scopes)
	if err != nil {
		return fmt.Errorf("mint token: %w", err)
	}

	if cachePath != "" {
		if err := gcp.StoreToken(cachePath, token); err != nil {
			return fmt.Errorf("store token: %w", err)
		}
	}

	emit(token.AccessToken, exportForm)

	return nil
}

func emit(token string, exportForm bool) {
	if exportForm {
		fmt.Printf("export GOOGLE_OAUTH_ACCESS_TOKEN=%s\n", token)
		return
	}

	fmt.Println(token)
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
