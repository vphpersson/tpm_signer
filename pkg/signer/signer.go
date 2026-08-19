// Package signer turns a TPM-resident RSA key into a crypto.Signer.
//
// The private key never leaves the TPM. Signing sends a digest to the chip and reads back a
// signature; there is no code path here that could produce private key material, because the TPM
// offers no command that would emit it for a key created with FixedTPM set.
package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/vphpersson/tpm_signer/pkg/keyfile"
)

// DefaultDevicePath is the kernel's TPM resource manager. Going through the resource manager
// rather than /dev/tpm0 lets several processes share the chip without fighting over its very
// small number of transient object slots.
const DefaultDevicePath = "/dev/tpmrm0"

// ownerHierarchy is TPM_RH_OWNER, the parent handle recorded in the key file.
const ownerHierarchy = 0x40000001

// SigningKeyTemplate describes the leaf key: RSA-2048, signing only, non-duplicable.
//
// RSA rather than the far nicer P-256 because Google accepts only RSA service account keys and
// signs assertions only with RS256.
var SigningKeyTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgRSA,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		// FixedTPM and FixedParent are what make the key file useless if it is copied elsewhere.
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
		// NoDA is deliberately left false. It keeps the key under the TPM's dictionary attack
		// lockout, which is the property that makes a short PIN defensible: guesses are rate
		// limited in hardware, so there is no offline attack to mount.
		NoDA: false,
	},
	Parameters: tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgRSA,
		&tpm2.TPMSRSAParms{
			// A null scheme leaves the choice to sign time, where RSASSA/SHA-256 is supplied.
			Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
			KeyBits: 2048,
		},
	),
}

// PINProvider yields the key's auth value. It is called once per signature so that a caller may
// prompt, cache for a while, or read from an agent, without this package caring which.
type PINProvider func() ([]byte, error)

// Signer implements crypto.Signer against a TPM-held key.
type Signer struct {
	key         *keyfile.Key
	devicePath  string
	pinProvider PINProvider
	publicKey   *rsa.PublicKey
}

// New builds a Signer. The public key is recovered from the key file, so no TPM access is needed
// until the first signature.
func New(key *keyfile.Key, devicePath string, pinProvider PINProvider) (*Signer, error) {
	if key == nil {
		return nil, nil_error.New("key")
	}
	if devicePath == "" {
		return nil, empty_error.New("device path")
	}
	if pinProvider == nil && !key.EmptyAuth {
		return nil, nil_error.New("pin provider")
	}

	publicKey, err := PublicKey(key)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("public key: %w", err))
	}

	return &Signer{key: key, devicePath: devicePath, pinProvider: pinProvider, publicKey: publicKey}, nil
}

// PublicKey recovers the RSA public key from a key file's public area.
func PublicKey(key *keyfile.Key) (*rsa.PublicKey, error) {
	if key == nil {
		return nil, nil_error.New("key")
	}

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](key.Public)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unmarshal public area: %w", altshiftErrors.ErrParseError, err),
		)
	}

	contents, err := public.Contents()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("public area contents: %w", err))
	}

	rsaParameters, err := contents.Parameters.RSADetail()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rsa detail: %w", err))
	}

	rsaUnique, err := contents.Unique.RSA()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rsa unique: %w", err))
	}

	publicKey, err := tpm2.RSAPub(rsaParameters, rsaUnique)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rsa pub: %w", err))
	}

	return publicKey, nil
}

// Public implements crypto.Signer.
func (signer *Signer) Public() crypto.PublicKey {
	return signer.publicKey
}

// Sign implements crypto.Signer. Only RSASSA-PKCS1-v1_5 over SHA-256 is supported, which is what
// RS256 needs; the rand argument is ignored because the TPM supplies its own entropy.
func (signer *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, nil_error.New("opts")
	}
	if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: PSS is not supported", altshiftErrors.ErrValidationError),
		)
	}
	if opts.HashFunc() != crypto.SHA256 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unsupported hash", altshiftErrors.ErrValidationError),
			opts.HashFunc().String(),
		)
	}
	if len(digest) != sha256.Size {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unexpected digest length", altshiftErrors.ErrValidationError),
			len(digest),
		)
	}

	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](signer.key.Public)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unmarshal public area: %w", altshiftErrors.ErrParseError, err),
		)
	}

	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](signer.key.Private)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unmarshal private area: %w", altshiftErrors.ErrParseError, err),
		)
	}

	device, err := linuxtpm.Open(signer.devicePath)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("open tpm: %w", err), signer.devicePath)
	}
	defer func() {
		_ = device.Close()
	}()

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(device)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("create primary: %w", err))
	}
	defer flushContext(device, primary.ObjectHandle)

	primaryPublic, err := primary.OutPublic.Contents()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("primary public contents: %w", err))
	}

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: *private,
		InPublic:  *public,
	}.Execute(device)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("load key: %w", err))
	}
	defer flushContext(device, loaded.ObjectHandle)

	var pin []byte
	if signer.pinProvider != nil {
		pin, err = signer.pinProvider()
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("pin provider: %w", err))
		}
		defer zero(pin)
	}

	// The session is salted to the primary and encrypts command parameters, so the PIN is never
	// on the wire: it keys an HMAC instead. On a discrete TPM this is what defeats bus sniffing.
	session, closeSession, err := tpm2.HMACSession(
		device,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Auth(pin),
		tpm2.Salted(primary.ObjectHandle, *primaryPublic),
		tpm2.AESEncryption(128, tpm2.EncryptIn),
	)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("hmac session: %w", err))
	}
	defer func() {
		_ = closeSession()
	}()

	signed, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   session,
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(device)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("tpm sign: %w", err))
	}

	signature, err := signed.Signature.Signature.RSASSA()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rsassa signature: %w", err))
	}

	return signature.Sig.Buffer, nil
}

// CreateKey generates a signing key inside the TPM. The private half is produced by the chip and
// never exists outside it; what comes back is only the wrapped blob for the key file.
func CreateKey(devicePath string, pin []byte, description string) (*keyfile.Key, error) {
	if devicePath == "" {
		return nil, empty_error.New("device path")
	}

	device, err := linuxtpm.Open(devicePath)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("open tpm: %w", err), devicePath)
	}
	defer func() {
		_ = device.Close()
	}()

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(device)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("create primary: %w", err))
	}
	defer flushContext(device, primary.ObjectHandle)

	primaryPublic, err := primary.OutPublic.Contents()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("primary public contents: %w", err))
	}

	// Creation carries the PIN into the chip, so it gets the same encrypted session treatment as
	// signing does.
	session, closeSession, err := tpm2.HMACSession(
		device,
		tpm2.TPMAlgSHA256,
		16,
		tpm2.Salted(primary.ObjectHandle, *primaryPublic),
		tpm2.AESEncryption(128, tpm2.EncryptIn),
	)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("hmac session: %w", err))
	}
	defer func() {
		_ = closeSession()
	}()

	created, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   session,
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: pin},
			},
		},
		InPublic: tpm2.New2B(SigningKeyTemplate),
	}.Execute(device)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("create key: %w", err))
	}

	return &keyfile.Key{
		Description: description,
		EmptyAuth:   len(pin) == 0,
		Parent:      ownerHierarchy,
		Public:      tpm2.Marshal(&created.OutPublic),
		Private:     tpm2.Marshal(&created.OutPrivate),
	}, nil
}

// flushContext releases a transient object slot. TPMs have very few, and leaking them wedges
// later operations until something resets the chip.
func flushContext(device transport.TPM, handle tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: handle}.Execute(device)
}

func zero(buffer []byte) {
	for index := range buffer {
		buffer[index] = 0
	}
}
