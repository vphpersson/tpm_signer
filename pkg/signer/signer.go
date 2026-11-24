// Package signer turns a TPM-resident RSA or ECC key into a crypto.Signer.
//
// The private key never leaves the TPM. Signing sends a digest to the chip and reads back a
// signature; there is no code path here that could produce private key material, because the TPM
// offers no command that would emit it for a key created with FixedTPM set.
package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"unicode/utf8"

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

const (
	// MinimumPINLength is the shortest PIN a new key is given, in characters. What makes a short PIN
	// defensible is the dictionary attack lockout, which on capa allows 31 guesses and then about
	// 144 a day: six digits take years to exhaust at that rate, four take weeks, and one is inside
	// the first allowance. Only new keys are held to it; a key made before keeps its PIN.
	MinimumPINLength = 6
	// MaximumPINLength is the longest auth value a key with a SHA-256 name can have: the TPM
	// refuses one longer than the name algorithm's digest.
	MaximumPINLength = sha256.Size
)

// ValidateNewPIN refuses a PIN too short for a new key, or too long for the TPM to take, or one
// holding a NUL byte. The length is counted in characters, as the lockout arithmetic assumes:
// three letters outside ASCII are six bytes but nowhere near as many guesses as six digits. A NUL
// is refused because go-tpm cuts the HMAC key at the first one while the TPM takes the whole value,
// so a PIN with one inside can never authorize, and one of NULs alone is no PIN to the TPM at all.
func ValidateNewPIN(pin []byte) error {
	if characters := utf8.RuneCount(pin); characters < MinimumPINLength {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a new PIN must be at least %d characters", altshiftErrors.ErrValidationError, MinimumPINLength),
			characters,
		)
	}
	if index := bytes.IndexByte(pin, 0); index >= 0 {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a PIN cannot hold a NUL byte", altshiftErrors.ErrValidationError),
			index,
		)
	}
	if len(pin) > MaximumPINLength {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a PIN can be at most %d bytes", altshiftErrors.ErrValidationError, MaximumPINLength),
			len(pin),
		)
	}

	return nil
}

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
// prompt, cache for a while, or read from an agent, without this package caring which. The slice
// stays the provider's: Sign copies it, and zeroes only its copy once the signature is made, so a
// provider that caches may hand out the same slice every time. Scrubbing that slice when it is no
// longer wanted is the provider's business.
type PINProvider func() ([]byte, error)

// Signer implements crypto.Signer against a TPM-held key.
type Signer struct {
	key         *keyfile.Key
	devicePath  string
	pinProvider PINProvider
	publicKey   crypto.PublicKey
	// allowSHA1 lets an RSA key sign SHA-1 digests as well as SHA-256 ones. See AllowSHA1.
	allowSHA1 bool
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

	if _, err := signatureScheme(publicKey, crypto.SHA256); err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("signature scheme: %w", err))
	}

	return &Signer{
		key:         key,
		devicePath:  devicePath,
		pinProvider: pinProvider,
		publicKey:   publicKey,
	}, nil
}

// AllowSHA1 lets the signer sign SHA-1 digests, PKCS #1 v1.5, as well as SHA-256 ones. Only an RSA
// key can.
//
// This is for a protocol that requires it and for nothing else. The Android Debug Bridge proves a
// host by having it sign twenty random bytes of the device's choosing as though they were a SHA-1
// digest, so whoever poses as the device chooses the digest, and gets back a signature good for any
// message with that SHA-1 hash. A key that does this must therefore sign for that protocol alone:
// keep a key of its own for it, never one that signs anything a SHA-1 signature could be mistaken
// for.
func (signer *Signer) AllowSHA1() error {
	if signer == nil {
		return nil_error.New("signer")
	}

	if _, ok := signer.publicKey.(*rsa.PublicKey); !ok {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: SHA-1 signatures are for RSA keys only", altshiftErrors.ErrValidationError),
			fmt.Sprintf("%T", signer.publicKey),
		)
	}

	signer.allowSHA1 = true

	return nil
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
// is made here, from the kind of key — RSASSA-PKCS1-v1_5 for RSA, ECDSA for ECC — and the hash the
// digest was made with: SHA-256, or SHA-1 for an RSA key whose signer allows it.
func signatureScheme(publicKey crypto.PublicKey, hash crypto.Hash) (*tpm2.TPMTSigScheme, error) {
	var hashAlgorithm tpm2.TPMAlgID

	switch hash {
	case crypto.SHA256:
		hashAlgorithm = tpm2.TPMAlgSHA256
	case crypto.SHA1:
		hashAlgorithm = tpm2.TPMAlgSHA1
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unsupported hash", altshiftErrors.ErrValidationError),
			hash.String(),
		)
	}

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

	if hash == crypto.SHA1 && algorithm != tpm2.TPMAlgRSASSA {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: SHA-1 signatures are for RSA keys only", altshiftErrors.ErrValidationError),
		)
	}

	return &tpm2.TPMTSigScheme{
		Scheme:  algorithm,
		Details: tpm2.NewTPMUSigScheme(algorithm, &tpm2.TPMSSchemeHash{HashAlg: hashAlgorithm}),
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
// An RSA signer that AllowSHA1 was called on also signs a SHA-1 digest. The rand argument is ignored
// because the TPM supplies its own entropy.
func (signer *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, nil_error.New("opts")
	}
	if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: PSS is not supported", altshiftErrors.ErrValidationError),
		)
	}

	hash := opts.HashFunc()
	if hash != crypto.SHA256 && (hash != crypto.SHA1 || !signer.allowSHA1) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unsupported hash", altshiftErrors.ErrValidationError),
			hash.String(),
		)
	}
	if len(digest) != hash.Size() {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unexpected digest length", altshiftErrors.ErrValidationError),
			len(digest),
		)
	}

	scheme, err := signatureScheme(signer.publicKey, hash)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("signature scheme: %w", err))
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
	// Before the PIN is asked for, and before a session is salted to this key.
	if err := verifyParent(signer.key.ParentName, primaryPublic); err != nil {
		return nil, fmt.Errorf("verify parent: %w", err)
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

	pin, err := signer.authValue()
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("auth value: %w", err))
	}
	defer zero(pin)

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
		InScheme:   *scheme,
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

// authValue is the PIN for one signature: a copy of what the provider returned, for Sign to zero.
// Zeroing the provider's own slice instead would leave a provider that keeps the PIN holding
// zeros, and the TPM drops trailing zeros from an auth value, so the next signature would be
// attempted with an empty PIN -- a failure that counts toward the chip-wide lockout.
func (signer *Signer) authValue() ([]byte, error) {
	if signer.pinProvider == nil {
		return nil, nil
	}

	provided, err := signer.pinProvider()
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("pin provider: %w", err))
	}
	// An empty PIN for a key that has one cannot succeed, and the failure would count toward the
	// lockout all the same.
	if len(provided) == 0 && !signer.key.EmptyAuth {
		return nil, empty_error.New("pin")
	}

	return bytes.Clone(provided), nil
}

// CreateKey generates a signing key inside the TPM. The private half is produced by the chip and
// never exists outside it; what comes back is only the wrapped blob for the key file. An empty pin
// makes a key that anything able to reach the TPM can sign with; any other is held to
// ValidateNewPIN before the TPM is opened.
func CreateKey(devicePath string, keyType KeyType, pin []byte, description string) (*keyfile.Key, error) {
	if devicePath == "" {
		return nil, empty_error.New("device path")
	}
	if len(pin) != 0 {
		if err := ValidateNewPIN(pin); err != nil {
			return nil, fmt.Errorf("validate new pin: %w", err)
		}
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

	// Recorded in the key file, so that every signature can check that the storage root key the
	// session is salted to is this one.
	name, err := parentName(primaryPublic)
	if err != nil {
		return nil, fmt.Errorf("parent name: %w", err)
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

	createdPublic, err := created.OutPublic.Contents()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("created public contents: %w", err))
	}
	if err := checkCreated(template, createdPublic); err != nil {
		return nil, fmt.Errorf("check created: %w", err)
	}

	return &keyfile.Key{
		Description: description,
		EmptyAuth:   len(pin) == 0,
		Parent:      ownerHierarchy,
		Public:      tpm2.Marshal(&created.OutPublic),
		Private:     tpm2.Marshal(&created.OutPrivate),
		ParentName:  name,
	}, nil
}

// checkCreated holds the key the TPM made to the template it was asked for. TPM2_Create copies the
// object attributes from the template, so anything but an exact match means something other than
// a TPM doing as asked answered at the device. Above all FixedTPM, FixedParent and
// SensitiveDataOrigin: without them the key could be duplicated off the chip, or its private half
// came from outside it, and the key file would be nothing like what tpm-keygen says it is.
func checkCreated(template *tpm2.TPMTPublic, created *tpm2.TPMTPublic) error {
	if template == nil {
		return nil_error.New("template")
	}
	if created == nil {
		return nil_error.New("created")
	}

	if created.Type != template.Type || created.NameAlg != template.NameAlg {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the created key is not of the kind asked for", altshiftErrors.ErrVerificationError),
			created.Type, template.Type, created.NameAlg, template.NameAlg,
		)
	}
	if created.ObjectAttributes != template.ObjectAttributes {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the created key's attributes differ from the template's", altshiftErrors.ErrVerificationError),
			fmt.Sprintf("%+v", created.ObjectAttributes), fmt.Sprintf("%+v", template.ObjectAttributes),
		)
	}

	return nil
}

// parentName is the TPM name of a storage root key: its name algorithm, and the digest of its
// public area under it.
func parentName(public *tpm2.TPMTPublic) ([]byte, error) {
	if public == nil {
		return nil, nil_error.New("public")
	}

	name, err := tpm2.ObjectName(public)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("object name: %w", err))
	}
	if name == nil || len(name.Buffer) == 0 {
		return nil, empty_error.New("object name")
	}

	return name.Buffer, nil
}

// verifyParent checks the storage root key CreatePrimary returned against the name recorded when
// the key was made. Nothing else vouches for it, and the session is salted to it: on a discrete
// TPM, an interposer on the bus that put its own key in the answer, and passed the salt on to the
// real one, would learn the session key -- and with it the PIN, which creation sends encrypted
// under that key, or enough to guess it offline, outside the lockout, from the HMAC a signature
// is authorized with. A firmware TPM has no such bus.
//
// It guards signatures only. The name it checks against was taken unverified when the key was
// made, so an interposer present then has already read the PIN and had its own name recorded.
//
// A key file with no recorded name, made before it was recorded or by another tool, is accepted:
// there is nothing to check it against.
func verifyParent(recorded []byte, public *tpm2.TPMTPublic) error {
	if len(recorded) == 0 {
		return nil
	}

	name, err := parentName(public)
	if err != nil {
		return fmt.Errorf("parent name: %w", err)
	}
	if !bytes.Equal(name, recorded) {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: the TPM's storage root key is not the one the key was created under",
				altshiftErrors.ErrVerificationError,
			),
			name, recorded,
		)
	}

	return nil
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
