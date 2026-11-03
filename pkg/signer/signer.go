// Package signer turns a TPM-resident RSA or ECC key into a crypto.Signer.
//
// The private key never leaves the TPM. Signing sends a digest to the chip and reads back a
// signature; there is no code path here that could produce private key material, because the TPM
// offers no command that would emit it for a key created with FixedTPM set.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

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

// KeyType names the kind of key CreateKey makes.
type KeyType string

const (
	// KeyTypeRSA2048 is what Google needs: it accepts only RSA service account keys and signs
	// assertions only with RS256.
	KeyTypeRSA2048 KeyType = "rsa-2048"
	// KeyTypeECCP256 is NIST P-256, for ES256. It is far quicker to create and to sign with, and
	// is the choice wherever the far end does not insist on RSA.
	KeyTypeECCP256 KeyType = "ecc-p256"
)

// DefaultKeyType is RSA-2048, which is what the GCP token minter needs.
const DefaultKeyType = KeyTypeRSA2048

// p256CoordinateSize is the byte length of a P-256 field element.
const p256CoordinateSize = 32

// KeyTemplate describes the leaf key: signing only, non-duplicable, with a null scheme so that the
// signature scheme is chosen at sign time.
//
// emptyAuth is whether the key is created without a PIN. Such a key is exempt from the dictionary
// attack lockout, because there is no auth value to guess; leaving it under the lockout would buy
// nothing and would let failed PINs against other keys on the chip lock an unattended job out.
func KeyTemplate(keyType KeyType, emptyAuth bool) (*tpm2.TPMTPublic, error) {
	attributes := tpm2.TPMAObject{
		// FixedTPM and FixedParent are what make the key file useless if it is copied elsewhere.
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		SignEncrypt:         true,
		// A key with a PIN stays under the TPM's dictionary attack lockout, which is the property
		// that makes a short PIN defensible: guesses are rate limited in hardware, so there is no
		// offline attack to mount.
		NoDA: emptyAuth,
	}

	switch keyType {
	case KeyTypeRSA2048:
		return &tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgRSA,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: attributes,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					// A null scheme leaves the choice to sign time, where RSASSA/SHA-256 is supplied.
					Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
					KeyBits: 2048,
				},
			),
		}, nil
	case KeyTypeECCP256:
		return &tpm2.TPMTPublic{
			Type:             tpm2.TPMAlgECC,
			NameAlg:          tpm2.TPMAlgSHA256,
			ObjectAttributes: attributes,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
					// A null scheme leaves the choice to sign time, where ECDSA/SHA-256 is supplied.
					Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
					CurveID: tpm2.TPMECCNistP256,
					KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
				},
			),
		}, nil
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unsupported key type", altshiftErrors.ErrValidationError),
			string(keyType),
		)
	}
}

// PINProvider yields the key's auth value. It is called once per signature so that a caller may
// prompt, cache for a while, or read from an agent, without this package caring which. The slice is
// the signer's: it is zeroed once the signature is made, so a provider that caches must return a
// copy each time, or the next signature is attempted with a PIN of zeros and counts as a failure.
type PINProvider func() ([]byte, error)

// Signer implements crypto.Signer against a TPM-held key.
type Signer struct {
	key         *keyfile.Key
	devicePath  string
	pinProvider PINProvider
	publicKey   crypto.PublicKey
	scheme      *tpm2.TPMTSigScheme
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

	scheme, err := signatureScheme(publicKey)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("signature scheme: %w", err))
	}

	return &Signer{
		key:         key,
		devicePath:  devicePath,
		pinProvider: pinProvider,
		publicKey:   publicKey,
		scheme:      scheme,
	}, nil
}

// PublicKey recovers the public key from a key file's public area: an *rsa.PublicKey for an RSA
// key, an *ecdsa.PublicKey for a P-256 one.
func PublicKey(key *keyfile.Key) (crypto.PublicKey, error) {
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

	switch contents.Type {
	case tpm2.TPMAlgRSA:
		return rsaPublicKey(contents)
	case tpm2.TPMAlgECC:
		return eccPublicKey(contents)
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unsupported key algorithm", altshiftErrors.ErrValidationError),
			contents.Type,
		)
	}
}

func rsaPublicKey(contents *tpm2.TPMTPublic) (*rsa.PublicKey, error) {
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

// eccPublicKey accepts P-256 only: Sign takes SHA-256 digests, which is the pairing ES256 names.
// The point goes through ParseUncompressedPublicKey, so one that is not on the curve is refused
// here rather than at the first verification.
func eccPublicKey(contents *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	eccParameters, err := contents.Parameters.ECCDetail()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("ecc detail: %w", err))
	}
	if eccParameters.CurveID != tpm2.TPMECCNistP256 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unsupported curve", altshiftErrors.ErrValidationError),
			eccParameters.CurveID,
		)
	}

	eccUnique, err := contents.Unique.ECC()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("ecc unique: %w", err))
	}

	point, err := uncompressedPoint(eccUnique.X.Buffer, eccUnique.Y.Buffer, p256CoordinateSize)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("uncompressed point: %w", err))
	}

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: ecdsa parse uncompressed public key: %w", altshiftErrors.ErrParseError, err),
			point,
		)
	}

	return publicKey, nil
}

// uncompressedPoint renders the SEC 1 uncompressed form, 0x04 || X || Y, left-padding each
// coordinate to the field size, since the TPM may strip leading zero bytes.
func uncompressedPoint(x []byte, y []byte, size int) ([]byte, error) {
	if len(x) == 0 {
		return nil, empty_error.New("x")
	}
	if len(y) == 0 {
		return nil, empty_error.New("y")
	}
	if len(x) > size || len(y) > size {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: coordinate longer than the field", altshiftErrors.ErrValidationError),
			len(x), len(y), size,
		)
	}

	point := make([]byte, 1+2*size)
	point[0] = 0x04
	copy(point[1+size-len(x):1+size], x)
	copy(point[1+2*size-len(y):], y)

	return point, nil
}

// signatureScheme is the scheme Sign asks the TPM for. The keys carry a null scheme, so the choice
// is made here, from the kind of key: RSASSA-PKCS1-v1_5 for RSA, ECDSA for ECC, SHA-256 for both.
func signatureScheme(publicKey crypto.PublicKey) (*tpm2.TPMTSigScheme, error) {
	var algorithm tpm2.TPMAlgID
	switch publicKey.(type) {
	case *rsa.PublicKey:
		algorithm = tpm2.TPMAlgRSASSA
	case *ecdsa.PublicKey:
		algorithm = tpm2.TPMAlgECDSA
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unsupported public key type", altshiftErrors.ErrValidationError),
			fmt.Sprintf("%T", publicKey),
		)
	}

	return &tpm2.TPMTSigScheme{
		Scheme:  algorithm,
		Details: tpm2.NewTPMUSigScheme(algorithm, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
	}, nil
}

// ecdsaSignature is the ASN.1 SEQUENCE { r INTEGER, s INTEGER } that crypto.Signer promises for
// ECDSA, and that ecdsa.VerifyASN1 and crypto/x509 read.
type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// encodeSignature renders the TPM's signature in the form crypto.Signer promises: the raw
// PKCS #1 v1.5 signature for RSA, and the ASN.1 DER encoding of r and s for ECDSA. A JWS wants
// r || s instead; converting is the caller's business, as it is for any other crypto.Signer.
func encodeSignature(signature *tpm2.TPMTSignature) ([]byte, error) {
	if signature == nil {
		return nil, nil_error.New("signature")
	}

	switch signature.SigAlg {
	case tpm2.TPMAlgRSASSA:
		rsassa, err := signature.Signature.RSASSA()
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rsassa signature: %w", err))
		}

		return rsassa.Sig.Buffer, nil
	case tpm2.TPMAlgECDSA:
		ecdsaSigned, err := signature.Signature.ECDSA()
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("ecdsa signature: %w", err))
		}

		r := new(big.Int).SetBytes(ecdsaSigned.SignatureR.Buffer)
		s := new(big.Int).SetBytes(ecdsaSigned.SignatureS.Buffer)
		// Zero is never a valid r or s; seeing one means the TPM's answer is not a signature.
		if r.Sign() == 0 || s.Sign() == 0 {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: zero r or s in ecdsa signature", altshiftErrors.ErrValidationError),
			)
		}

		der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("asn1 marshal: %w", err))
		}

		return der, nil
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unexpected signature algorithm", altshiftErrors.ErrValidationError),
			signature.SigAlg,
		)
	}
}

// Public implements crypto.Signer.
func (signer *Signer) Public() crypto.PublicKey {
	return signer.publicKey
}

// Sign implements crypto.Signer over a SHA-256 digest: RSASSA-PKCS1-v1_5 for an RSA key, which is
// what RS256 needs, and ECDSA for a P-256 key, returned ASN.1 DER encoded as crypto.Signer requires.
// The rand argument is ignored because the TPM supplies its own entropy.
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
		Digest:     tpm2.TPM2BDigest{Buffer: digest},
		InScheme:   *signer.scheme,
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(device)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("tpm sign: %w", err))
	}

	signature, err := encodeSignature(&signed.Signature)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("encode signature: %w", err))
	}

	return signature, nil
}

// CreateKey generates a signing key inside the TPM. The private half is produced by the chip and
// never exists outside it; what comes back is only the wrapped blob for the key file. An empty pin
// makes a key that anything able to reach the TPM can sign with.
func CreateKey(devicePath string, keyType KeyType, pin []byte, description string) (*keyfile.Key, error) {
	if devicePath == "" {
		return nil, empty_error.New("device path")
	}

	template, err := KeyTemplate(keyType, len(pin) == 0)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("key template: %w", err))
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
		InPublic: tpm2.New2B(*template),
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
