package gcp

import (
	"context"
	"crypto"
	"fmt"
	"os"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	oauth2Token "github.com/altshiftab/utils_go/pkg/oauth2/types/token"
	"github.com/altshiftab/utils_go/pkg/oauth2/types/token_source"

	"github.com/vphpersson/tpm_signer/pkg/keyfile"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

// tokenMinter signs an assertion with the TPM-held key and exchanges it, every
// time it is asked. Reusing what it mints is NewReusable's job, which is where
// the rest of utils_go leaves it: a source that cached on its own would be a
// second implementation of the same mutex.
type tokenMinter struct {
	//nolint:containedctx // The TokenSource interface takes no context; the construction context is deliberately captured, as the delegation source does.
	ctx            context.Context
	signer         crypto.Signer
	client         *Client
	serviceAccount string
	scopes         []string
}

func (m *tokenMinter) Token() (*oauth2Token.Token, error) {
	if err := m.ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	token, err := m.client.MintToken(m.ctx, m.signer, m.serviceAccount, m.scopes)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("mint token: %w", err), m.serviceAccount)
	}
	if token == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("token"), m.serviceAccount)
	}

	return &oauth2Token.Token{
		AccessToken: token.AccessToken,
		TokenType:   "Bearer",
		Expiry:      token.Expiry,
	}, nil
}

// newTokenSource puts the reuse around the minter. Separate from NewTokenSource
// so that the composition is testable without a TPM key file to load.
func newTokenSource(
	ctx context.Context,
	keySigner crypto.Signer,
	client *Client,
	serviceAccount string,
	scopes []string,
) token_source.TokenSource {
	return token_source.NewReusable(nil, &tokenMinter{
		ctx:            ctx,
		signer:         keySigner,
		client:         client,
		serviceAccount: serviceAccount,
		scopes:         scopes,
	})
}

// TokenSourceOptions are what a token source is built from. KeyPath and
// ServiceAccount are required; the rest have defaults.
type TokenSourceOptions struct {
	// KeyPath is the TPM key file, as tpm-keygen wrote it.
	KeyPath string
	// ServiceAccount is the account the key is registered against, and the
	// account the minted tokens act as.
	ServiceAccount string
	// Scopes default to ScopeCloudPlatform.
	Scopes []string
	// DevicePath defaults to signer.DefaultDevicePath.
	DevicePath string
	// PINProvider is required only for a key created with one. A key under a
	// PIN is a poor fit for something unattended, which is why tpm-keygen
	// offers --no-pin.
	PINProvider signer.PINProvider
	// Client stands in for Google's token endpoint when not nil.
	Client *Client
}

// NewTokenSource returns a source of Google access tokens minted from a
// TPM-held key, reusing each until it is nearly spent.
//
// It is what a long-running program wants, where gcp-token is what a command
// line wants. A token lasts an hour, so a daemon given one at startup stops
// working an hour later; the alternative to minting as it goes is a service
// account key file, which is a bearer credential anyone who copies it can use
// from anywhere until it is revoked. Here nothing is on disk but a wrapped blob
// that is inert on any other machine, and what the process holds is an hour of
// access rather than the means to mint it forever.
//
// Nothing touches the TPM until the first token is asked for, and the signer
// opens the device per signature and closes it again -- so holding this for the
// life of a process holds no handle on the device.
func NewTokenSource(ctx context.Context, options *TokenSourceOptions) (token_source.TokenSource, error) {
	if ctx == nil {
		return nil, nil_error.New("context")
	}
	if options == nil {
		return nil, nil_error.New("options")
	}
	if options.KeyPath == "" {
		return nil, empty_error.New("key path")
	}
	if options.ServiceAccount == "" {
		return nil, empty_error.New("service account")
	}

	keyData, err := os.ReadFile(options.KeyPath) //nolint:gosec // The path is the one the caller named.
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("os read file (key): %w", err), options.KeyPath)
	}

	key, err := keyfile.Parse(keyData)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("keyfile parse: %w", err), options.KeyPath)
	}

	devicePath := options.DevicePath
	if devicePath == "" {
		devicePath = signer.DefaultDevicePath
	}

	keySigner, err := signer.New(key, devicePath, options.PINProvider)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("signer new: %w", err), options.ServiceAccount)
	}

	scopes := options.Scopes
	if len(scopes) == 0 {
		scopes = []string{ScopeCloudPlatform}
	}

	client := options.Client
	if client == nil {
		client = &Client{}
	}

	return newTokenSource(ctx, keySigner, client, options.ServiceAccount, scopes), nil
}
