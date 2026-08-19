package gcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// softwareKey stands in for the TPM. The package takes a crypto.Signer precisely so the assertion
// logic can be tested without hardware.
func softwareKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

func TestAssertion(t *testing.T) {
	t.Parallel()

	key := softwareKey(t)
	now := time.Unix(1_700_000_000, 0)

	testCases := []struct {
		name           string
		signer         crypto.Signer
		serviceAccount string
		scopes         []string
		lifetime       time.Duration
		expectErr      bool
	}{
		{
			name:           "valid",
			signer:         key,
			serviceAccount: "robot@project.iam.gserviceaccount.com",
			scopes:         []string{ScopeCloudPlatform},
			lifetime:       time.Hour,
		},
		{
			name:           "multiple scopes",
			signer:         key,
			serviceAccount: "robot@project.iam.gserviceaccount.com",
			scopes:         []string{ScopeCloudPlatform, "https://www.googleapis.com/auth/devstorage.read_only"},
			lifetime:       30 * time.Minute,
		},
		{name: "nil signer", serviceAccount: "a@b.com", scopes: []string{ScopeCloudPlatform}, lifetime: time.Hour, expectErr: true},
		{name: "no service account", signer: key, scopes: []string{ScopeCloudPlatform}, lifetime: time.Hour, expectErr: true},
		{name: "no scopes", signer: key, serviceAccount: "a@b.com", lifetime: time.Hour, expectErr: true},
		{name: "zero lifetime", signer: key, serviceAccount: "a@b.com", scopes: []string{ScopeCloudPlatform}, expectErr: true},
		{
			name:           "lifetime beyond the cap",
			signer:         key,
			serviceAccount: "a@b.com",
			scopes:         []string{ScopeCloudPlatform},
			lifetime:       2 * time.Hour,
			expectErr:      true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			assertion, err := Assertion(
				testCase.signer,
				testCase.serviceAccount,
				testCase.scopes,
				now,
				testCase.lifetime,
			)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			parts := strings.Split(assertion, ".")
			if len(parts) != 3 {
				t.Fatalf("expected 3 JWT segments, got %d", len(parts))
			}

			var header map[string]string
			decodeSegment(t, parts[0], &header)
			if header["alg"] != "RS256" {
				t.Errorf("alg = %q, want RS256", header["alg"])
			}

			var claims map[string]any
			decodeSegment(t, parts[1], &claims)
			if claims["iss"] != testCase.serviceAccount {
				t.Errorf("iss = %v, want %v", claims["iss"], testCase.serviceAccount)
			}
			if claims["aud"] != TokenEndpoint {
				t.Errorf("aud = %v, want %v", claims["aud"], TokenEndpoint)
			}
			if claims["scope"] != strings.Join(testCase.scopes, " ") {
				t.Errorf("scope = %v, want %v", claims["scope"], strings.Join(testCase.scopes, " "))
			}
			if got, want := claims["exp"], float64(now.Add(testCase.lifetime).Unix()); got != want {
				t.Errorf("exp = %v, want %v", got, want)
			}

			// The signature must verify, or Google would reject the assertion.
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
				t.Errorf("signature does not verify: %v", err)
			}
		})
	}
}

func decodeSegment(t *testing.T, segment string, target any) {
	t.Helper()

	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
}

func TestClientExchange(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		status     int
		body       string
		assertion  string
		expectErr  bool
		wantToken  string
		wantExpiry time.Duration
	}{
		{
			name:       "success",
			status:     http.StatusOK,
			body:       `{"access_token":"ya29.test","token_type":"Bearer","expires_in":3599}`,
			assertion:  "a.b.c",
			wantToken:  "ya29.test",
			wantExpiry: 3599 * time.Second,
		},
		{
			name:      "rejected assertion",
			status:    http.StatusBadRequest,
			body:      `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`,
			assertion: "a.b.c",
			expectErr: true,
		},
		{
			name:      "malformed response",
			status:    http.StatusOK,
			body:      `not json`,
			assertion: "a.b.c",
			expectErr: true,
		},
		{
			name:      "empty access token",
			status:    http.StatusOK,
			body:      `{"token_type":"Bearer","expires_in":3599}`,
			assertion: "a.b.c",
			expectErr: true,
		},
		{name: "empty assertion", assertion: "", expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if err := request.ParseForm(); err != nil {
					t.Errorf("parse form: %v", err)
				}
				if got := request.PostForm.Get("grant_type"); got != GrantTypeJWTBearer {
					t.Errorf("grant_type = %q, want %q", got, GrantTypeJWTBearer)
				}
				if got := request.PostForm.Get("assertion"); got != testCase.assertion {
					t.Errorf("assertion = %q, want %q", got, testCase.assertion)
				}
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(testCase.body))
			}))
			defer server.Close()

			client := &Client{Endpoint: server.URL}
			token, err := client.Exchange(context.Background(), testCase.assertion)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token.AccessToken != testCase.wantToken {
				t.Errorf("access token = %q, want %q", token.AccessToken, testCase.wantToken)
			}
			if remaining := time.Until(token.Expiry); remaining > testCase.wantExpiry || remaining < testCase.wantExpiry-time.Minute {
				t.Errorf("expiry %v is not about %v away", token.Expiry, testCase.wantExpiry)
			}
		})
	}
}

func TestTokenValid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		token  *Token
		margin time.Duration
		want   bool
	}{
		{name: "nil token", token: nil, want: false},
		{name: "empty access token", token: &Token{Expiry: time.Now().Add(time.Hour)}, want: false},
		{name: "fresh", token: &Token{AccessToken: "x", Expiry: time.Now().Add(time.Hour)}, want: true},
		{name: "expired", token: &Token{AccessToken: "x", Expiry: time.Now().Add(-time.Minute)}, want: false},
		{
			name:   "inside the refresh margin",
			token:  &Token{AccessToken: "x", Expiry: time.Now().Add(time.Minute)},
			margin: 5 * time.Minute,
			want:   false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.token.Valid(testCase.margin); got != testCase.want {
				t.Errorf("Valid() = %v, want %v", got, testCase.want)
			}
		})
	}
}
