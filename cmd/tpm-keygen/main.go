// Command tpm-keygen creates a signing key inside the TPM and writes the artefacts that go with it:
// the key file, which is useless on any other machine, and the public half -- as a self-signed
// certificate, which is the form Google's key upload endpoint accepts, and as a PKIX public key,
// which is what most anything else takes.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"

	"github.com/vphpersson/tpm_signer/pkg/pin"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

// config is what the command line asks for.
type config struct {
	keyPath         string
	certificatePath string
	publicKeyPath   string
	description     string
	devicePath      string
	subject         string
	keyType         string
	days            int
	noPIN           bool
}

// newParser declares the command line, bound to config. The certificate option is returned as well,
// so that the caller can ask whether it was given rather than defaulted.
func newParser(cfg *config) (*argument_parser.Parser, option.Option) {
	certificateOption := option.WithDefault(
		option.NewStringOption(
			'c',
			"cert-file",
			"where to write the public key as a self-signed certificate; always for rsa-2048, only when given for ecc-p256",
			false,
			&cfg.certificatePath,
		),
		defaultPath("gcp.crt"),
	)

	parser := &argument_parser.Parser{
		Description: "Create a signing key inside the TPM, RSA-2048 or ECC P-256, gated by a PIN unless --no-pin. " +
			"No file is ever overwritten.",
		ProgramName: "tpm-keygen",
		Options: []option.Option{
			option.WithDefault(
				option.WithChoices(
					option.NewStringOption('t', "type", "key type: rsa-2048 for Google, ecc-p256 for ES256", false, &cfg.keyType),
					string(signer.KeyTypeRSA2048),
					string(signer.KeyTypeECCP256),
				),
				string(signer.DefaultKeyType),
			),
			option.WithDefault(
				option.NewStringOption('f', "key-file", "where to write the TPM key file", false, &cfg.keyPath),
				defaultPath("gcp.tpm"),
			),
			certificateOption,
			option.NewStringOption('p', "public-key-file", "where to write the public key as a PKIX \"PUBLIC KEY\" PEM", false, &cfg.publicKeyPath),
			option.NewStringOption('n', "description", "label stored inside the key file", false, &cfg.description),
			option.WithDefault(
				option.NewStringOption('D', "device", "TPM device path", false, &cfg.devicePath),
				signer.DefaultDevicePath,
			),
			option.WithDefault(
				option.NewStringOption('s', "subject", "certificate common name", false, &cfg.subject),
				"tpm-signer",
			),
			option.WithDefault(
				option.NewIntOption('d', "days", "certificate validity in days, which bounds the uploaded key's life", false, &cfg.days),
				"365",
			),
			option.NewBoolOption(0, "no-pin", "create the key without a PIN, so anything running as you can sign", false, &cfg.noPIN),
		},
	}

	return parser, certificateOption
}

// wantsCertificate decides whether to write the certificate. RSA keys get one as they always have,
// since it is what Google's upload takes. An ECC key gets one only on request, since Google would
// refuse it; it must then be given some file to carry its public half out, or there would be no
// way to register it.
func wantsCertificate(keyType signer.KeyType, certificateGiven bool, publicKeyPath string) (bool, error) {
	switch keyType {
	case signer.KeyTypeRSA2048:
		return true, nil
	case signer.KeyTypeECCP256:
		if !certificateGiven && publicKeyPath == "" {
			return false, fmt.Errorf(
				"%w: an %s key needs --public-key-file or --cert-file to export its public half",
				altshiftErrors.ErrValidationError,
				keyType,
			)
		}
		return certificateGiven, nil
	default:
		return false, fmt.Errorf("%w: unsupported key type: %q", altshiftErrors.ErrValidationError, keyType)
	}
}

func run() error {
	cfg := &config{}
	parser, certificateOption := newParser(cfg)
	if err := parser.Validate(); err != nil {
		return fmt.Errorf("parser validate: %w", err)
	}
	parser.ParseOrExit()

	keyType := signer.KeyType(cfg.keyType)
	writeCertificate, err := wantsCertificate(keyType, parser.Given(certificateOption), cfg.publicKeyPath)
	if err != nil {
		return fmt.Errorf("outputs: %w", err)
	}

	paths := []string{cfg.keyPath}
	if writeCertificate {
		paths = append(paths, cfg.certificatePath)
	}
	if cfg.publicKeyPath != "" {
		paths = append(paths, cfg.publicKeyPath)
	}
	// Checked before the PIN is asked for and the TPM is put to work; writeNewFile checks again.
	if err := checkOutputs(paths); err != nil {
		return fmt.Errorf("outputs: %w", err)
	}

	description := cfg.description
	if description == "" {
		hostname, _ := os.Hostname()
		description = "tpm-signer@" + hostname
	}

	var pinValue []byte
	if !cfg.noPIN {
		pinValue, err = pin.PromptConfirmed(context.Background(), "New TPM key PIN: ", pin.DefaultTimeout)
		if err != nil {
			return fmt.Errorf("prompt pin: %w", err)
		}
		defer zero(pinValue)
	}

	key, err := signer.CreateKey(cfg.devicePath, keyType, pinValue, description)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}

	var pinProvider signer.PINProvider
	if !cfg.noPIN {
		pinProvider = func() ([]byte, error) { return bytes.Clone(pinValue), nil }
	}

	keySigner, err := signer.New(key, cfg.devicePath, pinProvider)
	if err != nil {
		return fmt.Errorf("new signer: %w", err)
	}

	var certificate []byte
	if writeCertificate {
		certificate, err = selfSign(keySigner, cfg.subject, cfg.days)
		if err != nil {
			return fmt.Errorf("self sign: %w", err)
		}
	}

	var publicKeyPEM []byte
	if cfg.publicKeyPath != "" {
		publicKeyPEM, err = marshalPublicKeyPEM(keySigner.Public())
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
	}

	keyPEM, err := key.Marshal()
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	outputs := []*output{{path: cfg.keyPath, data: keyPEM, mode: 0o600}}
	if writeCertificate {
		outputs = append(outputs, &output{path: cfg.certificatePath, data: certificate, mode: 0o644})
	}
	if cfg.publicKeyPath != "" {
		outputs = append(outputs, &output{path: cfg.publicKeyPath, data: publicKeyPEM, mode: 0o644})
	}
	if err := writeAll(outputs); err != nil {
		return fmt.Errorf("write all: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Key created inside the TPM. The private half never left the chip.\n\n")
	fmt.Fprintf(os.Stderr, "  type         %s\n", keyType)
	fmt.Fprintf(os.Stderr, "  key file     %s\n", cfg.keyPath)
	if writeCertificate {
		fmt.Fprintf(os.Stderr, "  certificate  %s\n", cfg.certificatePath)
	}
	if cfg.publicKeyPath != "" {
		fmt.Fprintf(os.Stderr, "  public key   %s\n", cfg.publicKeyPath)
	}
	if cfg.noPIN {
		fmt.Fprintf(os.Stderr, "\n  no PIN: anything running as you can make the TPM sign with this key.\n")
	} else {
		fmt.Fprintf(os.Stderr, "\n  PIN set, and the key is under the TPM's dictionary attack lockout.\n")
	}

	if keyType == signer.KeyTypeRSA2048 {
		fmt.Fprintf(os.Stderr, "\nUpload the public half:\n\n")
		fmt.Fprintf(os.Stderr, "  gcloud iam service-accounts keys upload %s --iam-account=SERVICE_ACCOUNT\n", cfg.certificatePath)
	}

	return nil
}

// signatureAlgorithm is the certificate signature a key makes: SHA-256 either way, which is the
// only digest the TPM signer accepts.
func signatureAlgorithm(publicKey crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return x509.SHA256WithRSA, nil
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA256, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf(
			"%w: unsupported public key type: %T",
			altshiftErrors.ErrValidationError,
			publicKey,
		)
	}
}

// selfSign wraps the public key in a certificate, signed by the TPM key itself. The signature is
// incidental; Google only reads the public key out of it, but producing it here is a first proof
// that the key works.
func selfSign(keySigner crypto.Signer, subject string, days int) ([]byte, error) {
	algorithm, err := signatureAlgorithm(keySigner.Public())
	if err != nil {
		return nil, fmt.Errorf("signature algorithm: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    algorithm,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, keySigner.Public(), keySigner)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// marshalPublicKeyPEM renders the public key as a PKIX SubjectPublicKeyInfo in a "PUBLIC KEY" PEM.
func marshalPublicKeyPEM(publicKey crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("x509 marshal pkix public key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func defaultPath(name string) string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return name
	}

	return filepath.Join(directory, "tpm-signer", name)
}

// checkOutputs refuses, before anything is created, output paths that name the same file twice or
// a file already there. Writing the public key over the key file would lose the key; writing a key
// file or certificate over an old one could lose a key whose public half is registered somewhere.
func checkOutputs(paths []string) error {
	seen := make(map[string]string, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("abs: %w", err)
		}
		if previous, ok := seen[absolute]; ok {
			return fmt.Errorf("%w: %s and %s name the same file", altshiftErrors.ErrValidationError, previous, path)
		}
		seen[absolute] = path

		if err := refuseExisting(path); err != nil {
			return fmt.Errorf("refuse existing: %w", err)
		}
	}

	return nil
}

// refuseExisting fails if anything, a dangling symlink included, is at path.
func refuseExisting(path string) error {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("%s: %w", path, fs.ErrExist)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("lstat: %w", err)
	}
}

// output is one file a run writes.
type output struct {
	path string
	data []byte
	mode os.FileMode
}

// writeAll writes each output as a new file, in order. If one fails, those already written are
// removed again, so that a failed run leaves nothing behind -- in particular no key file whose
// public half went nowhere, which nothing could register and a rerun would refuse to replace.
func writeAll(outputs []*output) error {
	written := make([]string, 0, len(outputs))
	for _, out := range outputs {
		if out == nil {
			continue
		}
		if err := writeNewFile(out.path, out.data, out.mode); err != nil {
			for _, path := range written {
				_ = os.Remove(path)
			}
			return fmt.Errorf("write new file %s: %w", out.path, err)
		}
		written = append(written, out.path)
	}

	return nil
}

// writeNewFile writes a file that must not already exist.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // The path is the one the caller named.
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

func zero(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "tpm-keygen: %v\n", err)
		os.Exit(1)
	}
}
