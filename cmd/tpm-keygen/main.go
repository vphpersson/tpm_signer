// Command tpm-keygen creates an RSA signing key inside the TPM and writes the two artefacts that
// go with it: the key file, which is useless on any other machine, and a self-signed certificate
// carrying the public key, which is the form Google's key upload endpoint accepts.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"

	"github.com/vphpersson/tpm_signer/pkg/pin"
	"github.com/vphpersson/tpm_signer/pkg/signer"
)

func run() error {
	var keyPath string
	var certificatePath string
	var description string
	var devicePath string
	var subject string
	var days int
	var noPIN bool

	parser := &argument_parser.Parser{
		Description: "Create an RSA-2048 signing key inside the TPM, gated by a PIN.",
		ProgramName: "tpm-keygen",
		Options: []option.Option{
			option.WithDefault(
				option.NewStringOption('f', "key-file", "where to write the TPM key file", false, &keyPath),
				defaultPath("gcp.tpm"),
			),
			option.WithDefault(
				option.NewStringOption('c', "cert-file", "where to write the public certificate", false, &certificatePath),
				defaultPath("gcp.crt"),
			),
			option.NewStringOption('n', "description", "label stored inside the key file", false, &description),
			option.WithDefault(
				option.NewStringOption('D', "device", "TPM device path", false, &devicePath),
				signer.DefaultDevicePath,
			),
			option.WithDefault(
				option.NewStringOption('s', "subject", "certificate common name", false, &subject),
				"tpm-signer",
			),
			option.WithDefault(
				option.NewIntOption('d', "days", "certificate validity in days, which bounds the uploaded key's life", false, &days),
				"365",
			),
			option.NewBoolOption(0, "no-pin", "create the key without a PIN, so anything running as you can sign", false, &noPIN),
		},
	}
	if err := parser.Validate(); err != nil {
		return fmt.Errorf("parser validate: %w", err)
	}
	parser.ParseOrExit()

	if description == "" {
		hostname, _ := os.Hostname()
		description = "tpm-signer@" + hostname
	}

	var pinValue []byte
	if !noPIN {
		var err error
		pinValue, err = pin.PromptConfirmed(context.Background(), "New TPM key PIN: ", pin.DefaultTimeout)
		if err != nil {
			return fmt.Errorf("prompt pin: %w", err)
		}
		defer zero(pinValue)
	}

	key, err := signer.CreateKey(devicePath, pinValue, description)
	if err != nil {
		return fmt.Errorf("create key: %w", err)
	}

	keySigner, err := signer.New(key, devicePath, func() ([]byte, error) { return pinValue, nil })
	if err != nil {
		return fmt.Errorf("new signer: %w", err)
	}

	certificate, err := selfSign(keySigner, subject, days)
	if err != nil {
		return fmt.Errorf("self sign: %w", err)
	}

	keyPEM, err := key.Marshal()
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	if err := writeFile(certificatePath, certificate, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Key created inside the TPM. The private half never left the chip.\n\n")
	fmt.Fprintf(os.Stderr, "  key file     %s\n", keyPath)
	fmt.Fprintf(os.Stderr, "  certificate  %s\n", certificatePath)
	if noPIN {
		fmt.Fprintf(os.Stderr, "\n  no PIN: anything running as you can make the TPM sign with this key.\n")
	} else {
		fmt.Fprintf(os.Stderr, "\n  PIN set, and the key is under the TPM's dictionary attack lockout.\n")
	}
	fmt.Fprintf(os.Stderr, "\nUpload the public half:\n\n")
	fmt.Fprintf(os.Stderr, "  gcloud iam service-accounts keys upload %s --iam-account=SERVICE_ACCOUNT\n", certificatePath)

	return nil
}

// selfSign wraps the public key in a certificate, signed by the TPM key itself. The signature is
// incidental; Google only reads the public key out of it, but producing it here is a first proof
// that the key works.
func selfSign(keySigner crypto.Signer, subject string, days int) ([]byte, error) {
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
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, keySigner.Public(), keySigner)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func defaultPath(name string) string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return name
	}

	return filepath.Join(directory, "tpm-signer", name)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	return os.WriteFile(path, data, mode)
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
