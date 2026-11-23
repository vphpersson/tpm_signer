// Package gcp mints Google Cloud access tokens from a crypto.Signer.
//
// It implements the JWT bearer flow: a self-signed assertion is exchanged at Google's token
// endpoint for a short-lived access token. Google accepts only RS256 here, and only RSA service
// account keys, which is why the TPM key is RSA rather than the faster P-256.
//
// Nothing in this package knows the key is in a TPM. It takes a crypto.Signer, so a software key
// works identically, which is what makes it testable without hardware.
package gcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

const (
	// TokenEndpoint is Google's OAuth 2.0 token endpoint.
	//nolint:gosec // G101: an endpoint URL is a protocol constant, not a credential.
	TokenEndpoint = "https://oauth2.googleapis.com/token"
	// GrantTypeJWTBearer selects the assertion flow.
	//nolint:gosec // G101: a grant type URN is a protocol constant, not a credential.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// ScopeCloudPlatform is the broad scope Terraform needs.
	//nolint:gosec // G101: a scope URL is a protocol constant, not a credential.
	ScopeCloudPlatform = "https://www.googleapis.com/auth/cloud-platform"

	// maxAssertionLifetime is the ceiling Google places on an assertion's validity.
	maxAssertionLifetime = time.Hour
	// assertionLifetime is how long an assertion MintToken signs stays good. It is exchanged the
	// moment it is made, so minutes are plenty, and whatever lifts one on the way has only that
	// long to trade it for tokens of its own.
	assertionLifetime = 5 * time.Minute
	// exchangeTimeout bounds the exchange when the caller brings no HTTP client of its own.
	exchangeTimeout = 30 * time.Second
)

var (
	// ErrTokenEndpointRejected reports that Google refused the assertion. It is most often a clock
	// skew, an unregistered public key, or a service account that does not match the key.
	ErrTokenEndpointRejected = errors.New("the token endpoint rejected the assertion")
	// ErrRedirectRefused reports that the token endpoint answered with a redirect, which is not
	// followed: following a 307 or 308 would post the assertion again, to wherever it pointed.
	ErrRedirectRefused = errors.New("the token endpoint redirected, and the assertion is not sent on")
)

// Token is an access token with the wall-clock time it stops working.
type Token struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type,omitzero"`
	Expiry      time.Time `json:"expiry,omitzero"`
}

// ValidateAccessToken refuses an access token with any character outside [A-Za-z0-9._~+/=-], the
// RFC 6750 b64token alphabet with '=' allowed anywhere. Google's tokens keep to it, and so a token
// that does not is not one of theirs: printed into a shell statement, an HTTP header or a JSON
// string, it could be code, a second header or a broken document. The error does not quote the
// token, which is a secret if it is anything.
func ValidateAccessToken(token string) error {
	if token == "" {
		return empty_error.New("access token")
	}

	for index := range len(token) {
		if !isTokenCharacter(token[index]) {
			return altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: access token has a character outside the b64token alphabet", altshiftErrors.ErrValidationError),
				index,
			)
		}
	}

	return nil
}

func isTokenCharacter(character byte) bool {
	switch {
	case 'A' <= character && character <= 'Z', 'a' <= character && character <= 'z', '0' <= character && character <= '9':
		return true
	default:
		return strings.IndexByte("._~+/=-", character) >= 0
	}
}

// Valid reports whether the token is usable, keeping a margin so a token does not expire midway
// through a long Terraform run.
func (token *Token) Valid(margin time.Duration) bool {
	if token == nil || token.AccessToken == "" {
		return false
	}
	return time.Now().Add(margin).Before(token.Expiry)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type,omitzero"`
	ExpiresIn   int    `json:"expires_in,omitzero"`
}

type errorResponse struct {
	Error            string `json:"error,omitzero"`
	ErrorDescription string `json:"error_description,omitzero"`
}

func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Assertion builds and signs the JWT that is traded for an access token.
func Assertion(
	signer crypto.Signer,
	serviceAccount string,
	scopes []string,
	issuedAt time.Time,
	lifetime time.Duration,
) (string, error) {
	if signer == nil {
		return "", nil_error.New("signer")
	}
	// An ECC key would sign happily and be refused by Google afterwards, a round trip and a TPM
	// signature later, with an error that does not say why.
	if _, isRSA := signer.Public().(*rsa.PublicKey); !isRSA {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: google accepts only RSA keys", altshiftErrors.ErrValidationError),
			fmt.Sprintf("%T", signer.Public()),
		)
	}
	if serviceAccount == "" {
		return "", empty_error.New("service account")
	}
	if len(scopes) == 0 {
		return "", empty_error.New("scopes")
	}
	if lifetime <= 0 || lifetime > maxAssertionLifetime {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: lifetime out of range", altshiftErrors.ErrValidationError),
			lifetime.String(),
		)
	}

	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("marshal header: %w", err))
	}

	claims, err := json.Marshal(map[string]any{
		"iss":   serviceAccount,
		"sub":   serviceAccount,
		"scope": strings.Join(scopes, " "),
		"aud":   TokenEndpoint,
		"iat":   issuedAt.Unix(),
		"exp":   issuedAt.Add(lifetime).Unix(),
	})
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("marshal claims: %w", err))
	}

	signingInput := encodeSegment(header) + "." + encodeSegment(claims)
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("sign assertion: %w", err))
	}

	return signingInput + "." + encodeSegment(signature), nil
}

// Client exchanges signed assertions for access tokens.
type Client struct {
	// HTTPClient is the client used for the exchange: a copy of it, rather, that never follows a
	// redirect. When nil, the exchange gets a client of its own with a 30-second timeout.
	HTTPClient *http.Client
	// Endpoint overrides the Google token endpoint. It exists so tests can point the exchange at
	// a local server; leave it empty in production.
	Endpoint string
}

func (client *Client) resolvedEndpoint() string {
	if client == nil || client.Endpoint == "" {
		return TokenEndpoint
	}

	return client.Endpoint
}

// resolvedHTTPClient is the client the exchange goes through. It is always a fresh one, so that
// refusing redirects never reaches into a client the caller shares with anything else.
func (client *Client) resolvedHTTPClient() *http.Client {
	resolved := &http.Client{Timeout: exchangeTimeout}
	if client != nil && client.HTTPClient != nil {
		copied := *client.HTTPClient
		resolved = &copied
	}
	resolved.CheckRedirect = refuseRedirect

	return resolved
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return ErrRedirectRefused
}

// Exchange trades a signed assertion for an access token.
func (client *Client) Exchange(ctx context.Context, assertion string) (*Token, error) {
	if assertion == "" {
		return nil, empty_error.New("assertion")
	}

	form := url.Values{}
	form.Set("grant_type", GrantTypeJWTBearer)
	form.Set("assertion", assertion)

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		client.resolvedEndpoint(),
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("new request: %w", err))
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.resolvedHTTPClient().Do(request)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("token request: %w", err))
	}
	if response == nil {
		return nil, nil_error.New("response")
	}
	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("read response body: %w", err))
	}

	if response.StatusCode != http.StatusOK {
		var failure errorResponse
		_ = json.Unmarshal(body, &failure)
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %s: %s", ErrTokenEndpointRejected, failure.Error, failure.ErrorDescription),
			response.StatusCode,
		)
	}

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unmarshal token response: %w", altshiftErrors.ErrParseError, err),
		)
	}
	if err := ValidateAccessToken(parsed.AccessToken); err != nil {
		return nil, fmt.Errorf("validate access token: %w", err)
	}

	return &Token{
		AccessToken: parsed.AccessToken,
		TokenType:   parsed.TokenType,
		Expiry:      time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second),
	}, nil
}

// MintToken signs an assertion and exchanges it in one step.
func (client *Client) MintToken(
	ctx context.Context,
	signer crypto.Signer,
	serviceAccount string,
	scopes []string,
) (*Token, error) {
	assertion, err := Assertion(signer, serviceAccount, scopes, time.Now(), assertionLifetime)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("assertion: %w", err))
	}

	token, err := client.Exchange(ctx, assertion)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("exchange: %w", err))
	}

	return token, nil
}
