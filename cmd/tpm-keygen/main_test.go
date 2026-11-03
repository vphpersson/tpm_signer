package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vphpersson/tpm_signer/pkg/signer"
)

func TestParseArguments(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                 string
		arguments            []string
		expectErr            bool
		wantKeyType          string
		wantKeyFile          string
		wantCertificateFile  string
		wantPublicKeyPath    string
		wantNoPIN            bool
		wantCertificateGiven bool
	}{
		{
			name:                "defaults are rsa, with a pin, to the gcp files",
			arguments:           nil,
			wantKeyType:         "rsa-2048",
			wantKeyFile:         "gcp.tpm",
			wantCertificateFile: "gcp.crt",
		},
		{
			name: "an unattended ecc key",
			arguments: []string{
				"--type", "ecc-p256", "--no-pin",
				"--key-file", "/k/job.tpm", "--public-key-file", "/k/job.pem",
			},
			wantKeyType:         "ecc-p256",
			wantKeyFile:         "job.tpm",
			wantCertificateFile: "gcp.crt",
			wantPublicKeyPath:   "/k/job.pem",
			wantNoPIN:           true,
		},
		{
			name:                 "short options, attached values",
			arguments:            []string{"-tecc-p256", "-c/k/job.crt", "-p", "/k/job.pem"},
			wantKeyType:          "ecc-p256",
			wantKeyFile:          "gcp.tpm",
			wantCertificateFile:  "job.crt",
			wantPublicKeyPath:    "/k/job.pem",
			wantCertificateGiven: true,
		},
		{
			name:                 "a certificate path given as its default still counts as given",
			arguments:            []string{"--cert-file=" + defaultPath("gcp.crt")},
			wantKeyType:          "rsa-2048",
			wantKeyFile:          "gcp.tpm",
			wantCertificateFile:  "gcp.crt",
			wantCertificateGiven: true,
		},
		{name: "a type outside the choices", arguments: []string{"--type", "ed25519"}, expectErr: true},
		{name: "a type with no value", arguments: []string{"--type"}, expectErr: true},
		{name: "an unknown option", arguments: []string{"--pin"}, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config{}
			parser, certificateOption := newParser(cfg)
			if err := parser.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}

			err := parser.ParseArgs(testCase.arguments)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if cfg.keyType != testCase.wantKeyType {
				t.Errorf("type = %q, want %q", cfg.keyType, testCase.wantKeyType)
			}
			if filepath.Base(cfg.keyPath) != testCase.wantKeyFile {
				t.Errorf("key file = %q, want one named %q", cfg.keyPath, testCase.wantKeyFile)
			}
			if filepath.Base(cfg.certificatePath) != testCase.wantCertificateFile {
				t.Errorf("certificate file = %q, want one named %q", cfg.certificatePath, testCase.wantCertificateFile)
			}
			if cfg.publicKeyPath != testCase.wantPublicKeyPath {
				t.Errorf("public key file = %q, want %q", cfg.publicKeyPath, testCase.wantPublicKeyPath)
			}
			if cfg.noPIN != testCase.wantNoPIN {
				t.Errorf("no pin = %v, want %v", cfg.noPIN, testCase.wantNoPIN)
			}
			if got := parser.Given(certificateOption); got != testCase.wantCertificateGiven {
				t.Errorf("certificate given = %v, want %v", got, testCase.wantCertificateGiven)
			}
			if cfg.days != 365 {
				t.Errorf("days = %d, want the default 365", cfg.days)
			}
			if cfg.devicePath != signer.DefaultDevicePath {
				t.Errorf("device = %q, want %q", cfg.devicePath, signer.DefaultDevicePath)
			}
		})
	}
}

func TestWantsCertificate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		keyType          signer.KeyType
		certificateGiven bool
		publicKeyPath    string
		expectErr        bool
		want             bool
	}{
		{name: "rsa always gets one", keyType: signer.KeyTypeRSA2048, want: true},
		{name: "rsa with a public key too", keyType: signer.KeyTypeRSA2048, publicKeyPath: "k.pem", want: true},
		{name: "ecc with a public key only", keyType: signer.KeyTypeECCP256, publicKeyPath: "k.pem", want: false},
		{name: "ecc with a certificate asked for", keyType: signer.KeyTypeECCP256, certificateGiven: true, want: true},
		{name: "ecc with nowhere to put its public half", keyType: signer.KeyTypeECCP256, expectErr: true},
		{name: "unknown type", keyType: "ed25519", publicKeyPath: "k.pem", expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := wantsCertificate(testCase.keyType, testCase.certificateGiven, testCase.publicKeyPath)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != testCase.want {
				t.Errorf("wants certificate = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestMarshalPublicKeyPEM(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	testCases := []struct {
		name      string
		publicKey crypto.PublicKey
		expectErr bool
	}{
		{name: "rsa", publicKey: &rsaKey.PublicKey},
		{name: "ecc p-256", publicKey: &eccKey.PublicKey},
		{name: "nil", publicKey: nil, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := marshalPublicKeyPEM(testCase.publicKey)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			block, rest := pem.Decode(encoded)
			if block == nil || block.Type != "PUBLIC KEY" {
				t.Fatal("output is not a PUBLIC KEY PEM")
			}
			if len(rest) != 0 {
				t.Errorf("%d bytes after the PEM block", len(rest))
			}

			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Fatalf("parse pkix public key: %v", err)
			}
			equaler, ok := parsed.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !equaler.Equal(testCase.publicKey) {
				t.Error("the PEM carries a different public key")
			}
		})
	}
}

func TestSelfSign(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	testCases := []struct {
		name          string
		key           crypto.Signer
		subject       string
		days          int
		expectErr     bool
		wantAlgorithm x509.SignatureAlgorithm
	}{
		{name: "one year", key: rsaKey, subject: "tpm-signer", days: 365, wantAlgorithm: x509.SHA256WithRSA},
		{name: "short lived", key: rsaKey, subject: "throwaway", days: 1, wantAlgorithm: x509.SHA256WithRSA},
		{name: "empty subject is allowed", key: rsaKey, subject: "", days: 30, wantAlgorithm: x509.SHA256WithRSA},
		{name: "ecc p-256", key: eccKey, subject: "tpm-signer", days: 365, wantAlgorithm: x509.ECDSAWithSHA256},
		{name: "ed25519 is not a tpm key", key: edKey, subject: "tpm-signer", days: 365, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := selfSign(testCase.key, testCase.subject, testCase.days)
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
			if certificate.SignatureAlgorithm != testCase.wantAlgorithm {
				t.Errorf("signature algorithm = %v, want %v", certificate.SignatureAlgorithm, testCase.wantAlgorithm)
			}
			// It is no CA, so CheckSignatureFrom would refuse it as a parent; check the signature itself.
			if err := certificate.CheckSignature(
				certificate.SignatureAlgorithm,
				certificate.RawTBSCertificate,
				certificate.Signature,
			); err != nil {
				t.Errorf("self signature does not verify: %v", err)
			}

			// Google reads the public key out of this certificate, so it must be the key's own.
			public, ok := certificate.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !public.Equal(testCase.key.Public()) {
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

// TestWriteNewFile checks that nothing is written over a file already there, and that a file is
// never created more permissive than asked for. The exact mode is not asserted because the umask
// legitimately removes bits, and honouring a restrictive umask is the correct behaviour rather than
// something to override.
func TestWriteNewFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	existing := filepath.Join(directory, "existing.tpm")
	if err := os.WriteFile(existing, []byte("registered key"), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	testCases := []struct {
		name          string
		path          string
		mode          os.FileMode
		mustBePrivate bool
		expectErr     bool
		wantContent   string
	}{
		{name: "private key", path: filepath.Join(directory, "key.tpm"), mode: 0o600, mustBePrivate: true, wantContent: "content"},
		{name: "public certificate", path: filepath.Join(directory, "cert.crt"), mode: 0o644, wantContent: "content"},
		{
			name:          "creates missing directories",
			path:          filepath.Join(directory, "nested", "deeper", "key.tpm"),
			mode:          0o600,
			mustBePrivate: true,
			wantContent:   "content",
		},
		{
			name:          "an existing file is left alone",
			path:          existing,
			mode:          0o600,
			mustBePrivate: true,
			expectErr:     true,
			wantContent:   "registered key",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := writeNewFile(testCase.path, []byte("content"), testCase.mode)
			if testCase.expectErr && err == nil {
				t.Error("expected an error, got none")
			}
			if !testCase.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			content, err := os.ReadFile(testCase.path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(content) != testCase.wantContent {
				t.Errorf("content = %q, want %q", content, testCase.wantContent)
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

// TestWriteAll checks that a run which fails part-way leaves nothing it wrote behind, so that no
// key file survives whose public half went nowhere.
func TestWriteAll(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		blockLast bool
		expectErr bool
	}{
		{name: "all written"},
		{name: "a failed last write takes the earlier ones with it", blockLast: true, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			outputs := []*output{
				{path: filepath.Join(directory, "key.tpm"), data: []byte("key"), mode: 0o600},
				{path: filepath.Join(directory, "key.crt"), data: []byte("certificate"), mode: 0o644},
				{path: filepath.Join(directory, "key.pem"), data: []byte("public key"), mode: 0o644},
			}
			if testCase.blockLast {
				// A regular file where a directory is needed makes the last write fail.
				blocker := filepath.Join(directory, "blocker")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatalf("write blocker: %v", err)
				}
				outputs[2].path = filepath.Join(blocker, "key.pem")
			}

			err := writeAll(outputs)
			if testCase.expectErr != (err != nil) {
				t.Fatalf("error = %v, want an error: %v", err, testCase.expectErr)
			}

			for index, out := range outputs {
				content, readErr := os.ReadFile(out.path)
				if testCase.expectErr {
					if readErr == nil {
						t.Errorf("output %d (%s) was left behind by a failed run", index, out.path)
					}
					continue
				}
				if readErr != nil {
					t.Errorf("read output %d: %v", index, readErr)
					continue
				}
				if string(content) != string(out.data) {
					t.Errorf("output %d = %q, want %q", index, content, out.data)
				}
			}
		})
	}
}

func TestCheckOutputs(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	existing := filepath.Join(directory, "gcp.crt")
	if err := os.WriteFile(existing, []byte("certificate of a registered key"), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}
	key := filepath.Join(directory, "job.tpm")

	testCases := []struct {
		name      string
		paths     []string
		expectErr bool
	}{
		{name: "fresh, distinct paths", paths: []string{key, filepath.Join(directory, "job.pem")}},
		{name: "a key file alone", paths: []string{key}},
		{name: "public key over the key file", paths: []string{key, key}, expectErr: true},
		{
			name:      "the same file spelled differently",
			paths:     []string{key, filepath.Join(directory, ".", "sub", "..", "job.tpm")},
			expectErr: true,
		},
		{name: "an existing certificate", paths: []string{key, existing}, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := checkOutputs(testCase.paths)
			if testCase.expectErr && err == nil {
				t.Fatal("expected an error, got none")
			}
			if !testCase.expectErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRefuseExisting(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	existing := filepath.Join(directory, "existing.tpm")
	if err := os.WriteFile(existing, []byte("key"), 0o600); err != nil {
		t.Fatalf("write existing: %v", err)
	}
	dangling := filepath.Join(directory, "dangling.tpm")
	if err := os.Symlink(filepath.Join(directory, "nowhere"), dangling); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	testCases := []struct {
		name      string
		path      string
		wantExist bool
	}{
		{name: "missing", path: filepath.Join(directory, "missing.tpm")},
		{name: "missing directory", path: filepath.Join(directory, "no", "such", "key.tpm")},
		{name: "existing file", path: existing, wantExist: true},
		{name: "dangling symlink", path: dangling, wantExist: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := refuseExisting(testCase.path)
			if got := errors.Is(err, fs.ErrExist); got != testCase.wantExist {
				t.Errorf("refused as existing = %v (%v), want %v", got, err, testCase.wantExist)
			}
			if !testCase.wantExist && err != nil {
				t.Errorf("unexpected error: %v", err)
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
