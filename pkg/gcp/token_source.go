package gcp

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"sync"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	oauth2Token "github.com/altshiftab/utils_go/pkg/oauth2/types/token"

	"github.com/vphpersson/tpm_signer/pkg/keyfile"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

// DefaultRefreshMargin is how much life a token must have left to be handed out
// again, so that one minted now does not expire during the call it is about to
// authenticate.
const DefaultRefreshMargin = 5 * time.Minute

// TokenSource mints Google access tokens from a TPM-held key, and mints another
// when the one it holds is nearly spent.
//
// It is what a long-running program wants, where gcp-token is what a command
// line wants. A token lasts an hour, so a daemon given one at startup stops
// working an hour later; the alternative to minting as it goes is a service
// account key file, which is a bearer credential anyone who copies it can use
// from anywhere until it is revoked. Here nothing is on disk but a wrapped blob
// that is inert on any other machine, and what the process holds is an hour of
// access rather than the means to mint it forever.
//
// The signer opens the TPM per signature and closes it again, so holding this
// for the life of a process holds no handle on the device.
type TokenSource struct {
	//nolint:containedctx // The TokenSource interface takes no context; the construction context is deliberately captured, as x/oauth2 and the delegation source both do.
	ctx            context.Context
	signer         crypto.Signer
	client         *Client
	serviceAccount string
	scopes         []string
	refreshMargin  time.Duration

	mutex sync.Mutex
	token *Token
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
	// RefreshMargin defaults to DefaultRefreshMargin.
	RefreshMargin time.Duration
}

// NewTokenSource reads the key file and returns a source that mints from it.
// Nothing touches the TPM until the first token is asked for.
func NewTokenSource(ctx context.Context, options *TokenSourceOptions) (*TokenSource, error) {
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

	refreshMargin := options.RefreshMargin
	if refreshMargin <= 0 {
		refreshMargin = DefaultRefreshMargin
	}

	return &TokenSource{
		ctx:            ctx,
		signer:         keySigner,
		client:         client,
		serviceAccount: options.ServiceAccount,
		scopes:         scopes,
		refreshMargin:  refreshMargin,
	}, nil
}

// Token returns a token with life left in it, minting one if the last has run
// down. It satisfies utils_go's token_source.TokenSource.
//
// Callers are serialised so that a burst of them mints once rather than once
// each: a signature costs the TPM about half a second, and the token it yields
// is good for an hour.
func (s *TokenSource) Token() (*oauth2Token.Token, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.token != nil && s.token.Valid(s.refreshMargin) {
		return asOauth2Token(s.token), nil
	}

	token, err := s.client.MintToken(s.ctx, s.signer, s.serviceAccount, s.scopes)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("mint token: %w", err), s.serviceAccount)
	}
	if token == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("token"), s.serviceAccount)
	}

	s.token = token

	return asOauth2Token(token), nil
}

func asOauth2Token(token *Token) *oauth2Token.Token {
	return &oauth2Token.Token{
		AccessToken: token.AccessToken,
		TokenType:   "Bearer",
		Expiry:      token.Expiry,
	}
}
