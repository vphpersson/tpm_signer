package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// A software key stands in for the TPM's: the package takes a crypto.Signer, so
// everything above the chip is testable without one.
func testSigner(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

// mintingServer answers every exchange with a token, and counts how many it was
// asked for.
func mintingServer(t *testing.T, expiresIn int) (*Client, func() int) {
	t.Helper()

	var mutex sync.Mutex
	var mints int

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		mutex.Lock()
		mints++
		issued := mints
		mutex.Unlock()

		writer.Header().Set("Content-Type", "application/json")
		if err := json.MarshalWrite(writer, map[string]any{
			"access_token": fmt.Sprintf("token-%d", issued),
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		}); err != nil {
			t.Errorf("marshal write: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	return &Client{Endpoint: server.URL}, func() int {
		mutex.Lock()
		defer mutex.Unlock()
		return mints
	}
}

func newTestTokenSource(t *testing.T, client *Client, refreshMargin time.Duration) *TokenSource {
	t.Helper()

	return &TokenSource{
		ctx:            t.Context(),
		signer:         testSigner(t),
		client:         client,
		serviceAccount: "poller@example.iam.gserviceaccount.com",
		scopes:         []string{ScopeCloudPlatform},
		refreshMargin:  refreshMargin,
	}
}

func TestTokenSourceMintsOnceWhileValid(t *testing.T) {
	t.Parallel()

	client, mints := mintingServer(t, 3600)
	source := newTestTokenSource(t, client, DefaultRefreshMargin)

	first, err := source.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if first.AccessToken == "" {
		t.Fatal("no access token")
	}
	if first.Type() != "Bearer" {
		t.Errorf("token type = %q, want Bearer", first.Type())
	}

	// An hour of life left, so nothing should go back to the TPM or the
	// endpoint for it.
	for range 5 {
		again, err := source.Token()
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if again.AccessToken != first.AccessToken {
			t.Errorf("token = %q, want the one already held (%q)", again.AccessToken, first.AccessToken)
		}
	}

	if got := mints(); got != 1 {
		t.Errorf("mints = %d, want 1", got)
	}
}

func TestTokenSourceMintsAgainWhenSpent(t *testing.T) {
	t.Parallel()

	// A token good for a minute, wanted with five minutes to spare: every call
	// finds it spent. This is the case a daemon meets after an hour, which is
	// the whole reason the source exists.
	client, mints := mintingServer(t, 60)
	source := newTestTokenSource(t, client, DefaultRefreshMargin)

	first, err := source.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	second, err := source.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	if second.AccessToken == first.AccessToken {
		t.Error("the spent token was handed out again")
	}
	if got := mints(); got != 2 {
		t.Errorf("mints = %d, want 2", got)
	}
}

func TestTokenSourceMintsOnceUnderConcurrentCallers(t *testing.T) {
	t.Parallel()

	client, mints := mintingServer(t, 3600)
	source := newTestTokenSource(t, client, DefaultRefreshMargin)

	var waitGroup sync.WaitGroup
	for range 16 {
		waitGroup.Go(func() {
			if _, err := source.Token(); err != nil {
				t.Errorf("token: %v", err)
			}
		})
	}
	waitGroup.Wait()

	// A signature costs the TPM about half a second; a burst must not cost
	// sixteen of them.
	if got := mints(); got != 1 {
		t.Errorf("mints = %d, want 1", got)
	}
}

func TestTokenSourceRefusesACancelledContext(t *testing.T) {
	t.Parallel()

	client, mints := mintingServer(t, 3600)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	source := newTestTokenSource(t, client, DefaultRefreshMargin)
	source.ctx = ctx

	if _, err := source.Token(); err == nil {
		t.Error("expected an error")
	}
	if got := mints(); got != 0 {
		t.Errorf("mints = %d, want 0", got)
	}
}

func TestNewTokenSource(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options *TokenSourceOptions
		wantErr bool
	}{
		{name: "no options", wantErr: true},
		{
			name:    "no key path",
			options: &TokenSourceOptions{ServiceAccount: "a@example.iam.gserviceaccount.com"},
			wantErr: true,
		},
		{
			name:    "no service account",
			options: &TokenSourceOptions{KeyPath: "/nonexistent"},
			wantErr: true,
		},
		{
			name: "a key file that is not there",
			options: &TokenSourceOptions{
				KeyPath:        "/nonexistent/gcp.tpm",
				ServiceAccount: "a@example.iam.gserviceaccount.com",
			},
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewTokenSource(t.Context(), testCase.options); (err != nil) != testCase.wantErr {
				t.Errorf("error = %v, want an error: %v", err, testCase.wantErr)
			}
		})
	}
}
