package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSelfSign(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	testCases := []struct {
		name      string
		subject   string
		days      int
		expectErr bool
	}{
		{name: "one year", subject: "tpm-signer", days: 365},
		{name: "short lived", subject: "throwaway", days: 1},
		{name: "empty subject is allowed", subject: "", days: 30},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := selfSign(key, testCase.subject, testCase.days)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			block, _ := pem.Decode(encoded)
			if block == nil || block.Type != "CERTIFICATE" {
				t.Fatal("output is not a PEM certificate")
			}

			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("parse certificate: %v", err)
			}
			if certificate.Subject.CommonName != testCase.subject {
				t.Errorf("common name = %q, want %q", certificate.Subject.CommonName, testCase.subject)
			}
			if certificate.SignatureAlgorithm != x509.SHA256WithRSA {
				t.Errorf("signature algorithm = %v, want SHA256WithRSA", certificate.SignatureAlgorithm)
			}

			// Google reads the public key out of this certificate, so it must be the key's own.
			public, ok := certificate.PublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatal("certificate public key is not RSA")
			}
			if public.N.Cmp(key.N) != 0 {
				t.Error("certificate carries a different public key")
			}

			// The validity window bounds the uploaded key's life, so it must land where asked.
			wantExpiry := time.Now().AddDate(0, 0, testCase.days)
			if delta := certificate.NotAfter.Sub(wantExpiry); delta > time.Hour || delta < -time.Hour {
				t.Errorf("NotAfter = %v, want about %v", certificate.NotAfter, wantExpiry)
			}
			if certificate.NotBefore.After(time.Now()) {
				t.Error("NotBefore is in the future, which would make the certificate unusable now")
			}
		})
	}
}

// TestWriteFile checks the property that matters: a file is never created more permissive than
// asked for. The exact mode is not asserted because the umask legitimately removes bits, and
// honouring a restrictive umask is the correct behaviour rather than something to override.
func TestWriteFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()

	testCases := []struct {
		name          string
		path          string
		mode          os.FileMode
		mustBePrivate bool
	}{
		{name: "private key", path: filepath.Join(directory, "key.tpm"), mode: 0o600, mustBePrivate: true},
		{name: "public certificate", path: filepath.Join(directory, "cert.crt"), mode: 0o644},
		{
			name:          "creates missing directories",
			path:          filepath.Join(directory, "nested", "deeper", "key.tpm"),
			mode:          0o600,
			mustBePrivate: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := writeFile(testCase.path, []byte("content"), testCase.mode); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			info, err := os.Stat(testCase.path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}

			got := info.Mode().Perm()
			if extra := got &^ testCase.mode; extra != 0 {
				t.Errorf("mode = %o, which is more permissive than the requested %o", got, testCase.mode)
			}
			if testCase.mustBePrivate && got&0o077 != 0 {
				t.Errorf("mode = %o, but the key file must not be readable by group or other", got)
			}
		})
	}
}

func TestDefaultPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		file string
	}{
		{name: "key file", file: "gcp.tpm"},
		{name: "certificate", file: "gcp.crt"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			path := defaultPath(testCase.file)
			if filepath.Base(path) != testCase.file {
				t.Errorf("path %q does not end in %q", path, testCase.file)
			}
		})
	}
}

func TestZero(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		buffer []byte
	}{
		{name: "pin sized", buffer: []byte("482913")},
		{name: "empty", buffer: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			zero(testCase.buffer)
			for index, value := range testCase.buffer {
				if value != 0 {
					t.Fatalf("byte %d was left as %d", index, value)
				}
			}
		})
	}
}
