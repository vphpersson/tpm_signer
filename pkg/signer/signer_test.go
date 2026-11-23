package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/google/go-tpm/tpm2"

	"github.com/vphpersson/tpm_signer/pkg/keyfile"
)

// publicArea builds a marshalled TPM2B_PUBLIC for an RSA modulus, so the parts of this package
// that run before the TPM is touched can be tested without hardware.
func publicArea(t *testing.T, modulus []byte) []byte {
	t.Helper()

	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
			KeyBits: 2048,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: modulus}),
	})

	return tpm2.Marshal(&public)
}

// eccPublicArea builds a marshalled TPM2B_PUBLIC for an ECC point on the given curve.
func eccPublicArea(t *testing.T, curveID tpm2.TPMECCCurve, x []byte, y []byte) []byte {
	t.Helper()

	template, err := KeyTemplate(KeyTypeECCP256, false)
	if err != nil {
		t.Fatalf("key template: %v", err)
	}
	template.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
		Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
		CurveID:   curveID,
		KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
	})
	template.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: x},
		Y: tpm2.TPM2BECCParameter{Buffer: y},
	})

	public := tpm2.New2B(*template)

	return tpm2.Marshal(&public)
}

// pointCoordinates splits a software key's public point into its fixed-width X and Y.
func pointCoordinates(t *testing.T, publicKey *ecdsa.PublicKey) ([]byte, []byte) {
	t.Helper()

	encoded, err := publicKey.Bytes()
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	size := (len(encoded) - 1) / 2

	return encoded[1 : 1+size], encoded[1+size:]
}

func testKey(t *testing.T) *keyfile.Key {
	t.Helper()

	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	private := tpm2.TPM2BPrivate{Buffer: []byte{0xde, 0xad, 0xbe, 0xef}}

	return &keyfile.Key{
		Parent:  ownerHierarchy,
		Public:  publicArea(t, software.N.Bytes()),
		Private: tpm2.Marshal(&private),
	}
}

func testECCKey(t *testing.T) (*keyfile.Key, *ecdsa.PrivateKey) {
	t.Helper()

	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	x, y := pointCoordinates(t, &software.PublicKey)
	private := tpm2.TPM2BPrivate{Buffer: []byte{0xde, 0xad, 0xbe, 0xef}}

	return &keyfile.Key{
		Parent:  ownerHierarchy,
		Public:  eccPublicArea(t, tpm2.TPMECCNistP256, x, y),
		Private: tpm2.Marshal(&private),
	}, software
}

// TestKeyTemplate pins the RSA template to what it was before key types existed, so that keys
// created for Google are made exactly as they always were.
func TestKeyTemplate(t *testing.T) {
	t.Parallel()

	legacyRSA := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			NoDA:                false,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
				KeyBits: 2048,
			},
		),
	}

	testCases := []struct {
		name       string
		keyType    KeyType
		emptyAuth  bool
		expectErr  bool
		wantType   tpm2.TPMAlgID
		wantNoDA   bool
		wantLegacy bool
	}{
		{name: "rsa with a pin is the legacy template", keyType: KeyTypeRSA2048, wantType: tpm2.TPMAlgRSA, wantLegacy: true},
		{name: "rsa without a pin is exempt from lockout", keyType: KeyTypeRSA2048, emptyAuth: true, wantType: tpm2.TPMAlgRSA, wantNoDA: true},
		{name: "ecc with a pin", keyType: KeyTypeECCP256, wantType: tpm2.TPMAlgECC},
		{name: "ecc without a pin is exempt from lockout", keyType: KeyTypeECCP256, emptyAuth: true, wantType: tpm2.TPMAlgECC, wantNoDA: true},
		{name: "default is rsa", keyType: DefaultKeyType, wantType: tpm2.TPMAlgRSA, wantLegacy: true},
		{name: "unknown type", keyType: "ed25519", expectErr: true},
		{name: "empty type", keyType: "", expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			template, err := KeyTemplate(testCase.keyType, testCase.emptyAuth)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if template.Type != testCase.wantType {
				t.Errorf("type = %v, want %v", template.Type, testCase.wantType)
			}
			if template.ObjectAttributes.NoDA != testCase.wantNoDA {
				t.Errorf("NoDA = %v, want %v", template.ObjectAttributes.NoDA, testCase.wantNoDA)
			}
			attributes := template.ObjectAttributes
			if !attributes.FixedTPM || !attributes.FixedParent || !attributes.SensitiveDataOrigin ||
				!attributes.UserWithAuth || !attributes.SignEncrypt {
				t.Errorf("attributes = %+v, want a fixed, TPM-generated signing key", attributes)
			}
			if attributes.Decrypt || attributes.Restricted {
				t.Errorf("attributes = %+v, want an unrestricted key that cannot decrypt", attributes)
			}
			if testCase.wantLegacy && !bytes.Equal(tpm2.Marshal(template), tpm2.Marshal(&legacyRSA)) {
				t.Error("rsa template differs from the one keys were always created with")
			}

			// The template must survive the trip through the wire format with its parameters intact.
			public := tpm2.New2B(*template)
			parsed, err := tpm2.Unmarshal[tpm2.TPM2BPublic](tpm2.Marshal(&public))
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			contents, err := parsed.Contents()
			if err != nil {
				t.Fatalf("contents: %v", err)
			}

			switch testCase.wantType {
			case tpm2.TPMAlgECC:
				parameters, err := contents.Parameters.ECCDetail()
				if err != nil {
					t.Fatalf("ecc detail: %v", err)
				}
				if parameters.CurveID != tpm2.TPMECCNistP256 {
					t.Errorf("curve = %v, want NIST P-256", parameters.CurveID)
				}
				if parameters.Scheme.Scheme != tpm2.TPMAlgNull {
					t.Errorf("scheme = %v, want null so that the scheme is chosen at sign time", parameters.Scheme.Scheme)
				}
			case tpm2.TPMAlgRSA:
				parameters, err := contents.Parameters.RSADetail()
				if err != nil {
					t.Fatalf("rsa detail: %v", err)
				}
				if parameters.KeyBits != 2048 {
					t.Errorf("key bits = %d, want 2048", parameters.KeyBits)
				}
				if parameters.Scheme.Scheme != tpm2.TPMAlgNull {
					t.Errorf("scheme = %v, want null so that the scheme is chosen at sign time", parameters.Scheme.Scheme)
				}
			default:
				t.Fatalf("no parameter checks for %v", testCase.wantType)
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	t.Parallel()

	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	eccKey, eccSoftware := testECCKey(t)
	x, y := pointCoordinates(t, &eccSoftware.PublicKey)

	// A key with a coordinate that starts with a zero byte, so that stripping it changes something.
	// One in 128 keys has one, so this takes a few hundred microseconds.
	var zeroLed *ecdsa.PrivateKey
	var zeroLedX, zeroLedY []byte
	for zeroLed == nil {
		candidate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		candidateX, candidateY := pointCoordinates(t, &candidate.PublicKey)
		if candidateX[0] == 0 || candidateY[0] == 0 {
			zeroLed, zeroLedX, zeroLedY = candidate, candidateX, candidateY
		}
	}
	strippedX := new(big.Int).SetBytes(zeroLedX).Bytes()
	strippedY := new(big.Int).SetBytes(zeroLedY).Bytes()
	if len(strippedX) == len(zeroLedX) && len(strippedY) == len(zeroLedY) {
		t.Fatal("no coordinate lost a leading zero, so the stripped case tests nothing")
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p384X, p384Y := pointCoordinates(t, &p384.PublicKey)

	// A point whose Y is off by one is not on the curve.
	offCurveY := new(big.Int).Add(new(big.Int).SetBytes(y), big.NewInt(1)).FillBytes(make([]byte, 32))

	testCases := []struct {
		name      string
		key       *keyfile.Key
		expectErr bool
		want      crypto.PublicKey
	}{
		{name: "rsa", key: &keyfile.Key{Public: publicArea(t, software.N.Bytes())}, want: &software.PublicKey},
		{name: "ecc p-256", key: eccKey, want: &eccSoftware.PublicKey},
		{
			// The TPM may strip a leading zero byte from a coordinate; the key must survive that.
			name: "ecc p-256 with stripped leading zeros",
			key:  &keyfile.Key{Public: eccPublicArea(t, tpm2.TPMECCNistP256, strippedX, strippedY)},
			want: &zeroLed.PublicKey,
		},
		{name: "ecc p-384 is refused", key: &keyfile.Key{Public: eccPublicArea(t, tpm2.TPMECCNistP384, p384X, p384Y)}, expectErr: true},
		{name: "ecc point off the curve", key: &keyfile.Key{Public: eccPublicArea(t, tpm2.TPMECCNistP256, x, offCurveY)}, expectErr: true},
		{name: "nil key", key: nil, expectErr: true},
		{name: "empty public area", key: &keyfile.Key{}, expectErr: true},
		{name: "garbage public area", key: &keyfile.Key{Public: []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04}}, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			publicKey, err := PublicKey(testCase.key)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			equaler, ok := publicKey.(interface{ Equal(crypto.PublicKey) bool })
			if !ok {
				t.Fatalf("public key %T cannot be compared", publicKey)
			}
			if !equaler.Equal(testCase.want) {
				t.Error("public key does not match the one in the public area")
			}
		})
	}
}

func TestUncompressedPoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		x         []byte
		y         []byte
		size      int
		expectErr bool
		want      []byte
	}{
		{name: "full width", x: []byte{1, 2}, y: []byte{3, 4}, size: 2, want: []byte{4, 1, 2, 3, 4}},
		{name: "short coordinates are left-padded", x: []byte{2}, y: []byte{4}, size: 2, want: []byte{4, 0, 2, 0, 4}},
		{name: "x longer than the field", x: []byte{1, 2, 3}, y: []byte{4}, size: 2, expectErr: true},
		{name: "y longer than the field", x: []byte{1}, y: []byte{2, 3, 4}, size: 2, expectErr: true},
		{name: "empty x", y: []byte{1}, size: 2, expectErr: true},
		{name: "empty y", x: []byte{1}, size: 2, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			point, err := uncompressedPoint(testCase.x, testCase.y, testCase.size)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(point, testCase.want) {
				t.Errorf("point = %x, want %x", point, testCase.want)
			}
		})
	}
}

func TestSignatureScheme(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	testCases := []struct {
		name      string
		publicKey crypto.PublicKey
		expectErr bool
		want      tpm2.TPMAlgID
	}{
		{name: "rsa signs with rsassa", publicKey: &rsaKey.PublicKey, want: tpm2.TPMAlgRSASSA},
		{name: "ecc signs with ecdsa", publicKey: &eccKey.PublicKey, want: tpm2.TPMAlgECDSA},
		{name: "ed25519 is not a tpm key", publicKey: edPublic, expectErr: true},
		{name: "nil", publicKey: nil, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			scheme, err := signatureScheme(testCase.publicKey)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scheme.Scheme != testCase.want {
				t.Errorf("scheme = %v, want %v", scheme.Scheme, testCase.want)
			}

			var details *tpm2.TPMSSchemeHash
			switch testCase.want {
			case tpm2.TPMAlgRSASSA:
				details, err = scheme.Details.RSASSA()
			case tpm2.TPMAlgECDSA:
				details, err = scheme.Details.ECDSA()
			default:
				t.Fatalf("no detail check for %v", testCase.want)
			}
			if err != nil {
				t.Fatalf("scheme details: %v", err)
			}
			if details.HashAlg != tpm2.TPMAlgSHA256 {
				t.Errorf("hash = %v, want SHA-256", details.HashAlg)
			}
		})
	}
}

// TestEncodeSignature feeds the encoder what a TPM returns, made by a software key, and checks that
// what comes out verifies the way a crypto.Signer's output must.
func TestEncodeSignature(t *testing.T) {
	t.Parallel()

	digest := sha256.Sum256([]byte("payload"))

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}

	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := ecdsa.SignASN1(rand.Reader, eccKey, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	var parsed ecdsaSignature
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("asn1 unmarshal: %v", err)
	}

	ecdsaTPMSignature := func(r []byte, s []byte) *tpm2.TPMTSignature {
		return &tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash:       tpm2.TPMAlgSHA256,
				SignatureR: tpm2.TPM2BECCParameter{Buffer: r},
				SignatureS: tpm2.TPM2BECCParameter{Buffer: s},
			}),
		}
	}

	testCases := []struct {
		name      string
		signature *tpm2.TPMTSignature
		expectErr bool
		verify    func([]byte) bool
	}{
		{
			name: "rsassa is passed through",
			signature: &tpm2.TPMTSignature{
				SigAlg: tpm2.TPMAlgRSASSA,
				Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: rsaSignature},
				}),
			},
			verify: func(signature []byte) bool {
				return rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest[:], signature) == nil
			},
		},
		{
			name:      "ecdsa is der encoded",
			signature: ecdsaTPMSignature(parsed.R.Bytes(), parsed.S.Bytes()),
			verify: func(signature []byte) bool {
				return ecdsa.VerifyASN1(&eccKey.PublicKey, digest[:], signature)
			},
		},
		{
			// A TPM returns r and s at the full field width; the INTEGERs must still be minimal.
			name:      "ecdsa with zero-padded r and s",
			signature: ecdsaTPMSignature(parsed.R.FillBytes(make([]byte, 33)), parsed.S.FillBytes(make([]byte, 33))),
			verify: func(signature []byte) bool {
				return ecdsa.VerifyASN1(&eccKey.PublicKey, digest[:], signature) && bytes.Equal(signature, der)
			},
		},
		{name: "ecdsa with zero r", signature: ecdsaTPMSignature([]byte{0}, parsed.S.Bytes()), expectErr: true},
		{name: "ecdsa with empty s", signature: ecdsaTPMSignature(parsed.R.Bytes(), nil), expectErr: true},
		{
			name: "rsapss is not what was asked for",
			signature: &tpm2.TPMTSignature{
				SigAlg: tpm2.TPMAlgRSAPSS,
				Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSAPSS, &tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: rsaSignature},
				}),
			},
			expectErr: true,
		},
		{name: "nil", signature: nil, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := encodeSignature(testCase.signature)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !testCase.verify(encoded) {
				t.Errorf("encoded signature %x does not verify", encoded)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	eccKey, _ := testECCKey(t)
	provider := func() ([]byte, error) { return []byte("123456"), nil }

	testCases := []struct {
		name        string
		key         *keyfile.Key
		devicePath  string
		pinProvider PINProvider
		expectErr   bool
		wantScheme  tpm2.TPMAlgID
	}{
		{name: "valid", key: key, devicePath: DefaultDevicePath, pinProvider: provider, wantScheme: tpm2.TPMAlgRSASSA},
		{name: "valid ecc", key: eccKey, devicePath: DefaultDevicePath, pinProvider: provider, wantScheme: tpm2.TPMAlgECDSA},
		{
			name:       "no pin provider is fine for an empty auth key",
			key:        &keyfile.Key{Parent: ownerHierarchy, EmptyAuth: true, Public: key.Public, Private: key.Private},
			devicePath: DefaultDevicePath,
			wantScheme: tpm2.TPMAlgRSASSA,
		},
		{
			name:       "no pin provider is fine for an empty auth ecc key",
			key:        &keyfile.Key{Parent: ownerHierarchy, EmptyAuth: true, Public: eccKey.Public, Private: eccKey.Private},
			devicePath: DefaultDevicePath,
			wantScheme: tpm2.TPMAlgECDSA,
		},
		{name: "nil key", devicePath: DefaultDevicePath, pinProvider: provider, expectErr: true},
		{name: "empty device path", key: key, pinProvider: provider, expectErr: true},
		{name: "pin required but no provider", key: key, devicePath: DefaultDevicePath, expectErr: true},
		{name: "pin required but no provider for ecc", key: eccKey, devicePath: DefaultDevicePath, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			signer, err := New(testCase.key, testCase.devicePath, testCase.pinProvider)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if signer.scheme.Scheme != testCase.wantScheme {
				t.Errorf("scheme = %v, want %v", signer.scheme.Scheme, testCase.wantScheme)
			}
		})
	}
}

// TestSignRejectsUnsupportedOptions covers the argument checks, which run before the TPM is
// opened and so need no hardware.
func TestSignRejectsUnsupportedOptions(t *testing.T) {
	t.Parallel()

	provider := func() ([]byte, error) { return []byte("123456"), nil }

	rsaSigner, err := New(testKey(t), DefaultDevicePath, provider)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	eccKey, _ := testECCKey(t)
	eccSigner, err := New(eccKey, DefaultDevicePath, provider)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	digest := sha256.Sum256([]byte("payload"))

	testCases := []struct {
		name   string
		signer *Signer
		digest []byte
		opts   crypto.SignerOpts
	}{
		{name: "nil opts", signer: rsaSigner, digest: digest[:], opts: nil},
		{name: "pss is not supported", signer: rsaSigner, digest: digest[:], opts: &rsa.PSSOptions{Hash: crypto.SHA256}},
		{name: "wrong hash", signer: rsaSigner, digest: digest[:], opts: crypto.SHA512},
		{name: "short digest", signer: rsaSigner, digest: digest[:16], opts: crypto.SHA256},
		{name: "ecc nil opts", signer: eccSigner, digest: digest[:], opts: nil},
		{name: "ecc pss is meaningless", signer: eccSigner, digest: digest[:], opts: &rsa.PSSOptions{Hash: crypto.SHA256}},
		{name: "ecc wrong hash", signer: eccSigner, digest: digest[:], opts: crypto.SHA384},
		{name: "ecc short digest", signer: eccSigner, digest: digest[:16], opts: crypto.SHA256},
		{name: "ecc long digest", signer: eccSigner, digest: append(digest[:], 0), opts: crypto.SHA256},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := testCase.signer.Sign(rand.Reader, testCase.digest, testCase.opts); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

// errNoTerminal stands in for a provider that cannot ask anyone.
var errNoTerminal = errors.New("no terminal")

// TestAuthValue asks for the PIN the way Sign does, twice, zeroing what it got the first time as
// Sign does when a signature is made.
func TestAuthValue(t *testing.T) {
	t.Parallel()

	pinKey := testKey(t)
	emptyAuthKey := &keyfile.Key{Parent: ownerHierarchy, EmptyAuth: true, Public: pinKey.Public, Private: pinKey.Private}

	testCases := []struct {
		name      string
		key       *keyfile.Key
		provider  func(pin []byte) PINProvider
		pin       []byte
		expectErr bool
		want      []byte
	}{
		{
			name:     "a provider that caches its slice gets the same pin back the second time",
			key:      pinKey,
			provider: func(pin []byte) PINProvider { return func() ([]byte, error) { return pin, nil } },
			pin:      []byte("482913"),
			want:     []byte("482913"),
		},
		{
			name:     "a provider that copies",
			key:      pinKey,
			provider: func(pin []byte) PINProvider { return func() ([]byte, error) { return bytes.Clone(pin), nil } },
			pin:      []byte("482913"),
			want:     []byte("482913"),
		},
		{
			name:      "an empty pin for a key that has one is refused before the tpm sees it",
			key:       pinKey,
			provider:  func(pin []byte) PINProvider { return func() ([]byte, error) { return pin, nil } },
			pin:       []byte{},
			expectErr: true,
		},
		{
			name:      "a provider that fails",
			key:       pinKey,
			provider:  func([]byte) PINProvider { return func() ([]byte, error) { return nil, errNoTerminal } },
			expectErr: true,
		},
		{
			name:     "no provider for a key without a pin",
			key:      emptyAuthKey,
			provider: func([]byte) PINProvider { return nil },
		},
		{
			name:     "an empty pin for a key without one",
			key:      emptyAuthKey,
			provider: func(pin []byte) PINProvider { return func() ([]byte, error) { return pin, nil } },
			pin:      []byte{},
			want:     []byte{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			pin := bytes.Clone(testCase.pin)
			signer, err := New(testCase.key, DefaultDevicePath, testCase.provider(pin))
			if err != nil {
				t.Fatalf("new signer: %v", err)
			}

			for attempt := range 2 {
				value, err := signer.authValue()
				if testCase.expectErr {
					if err == nil {
						t.Fatal("expected an error, got none")
					}
					return
				}
				if err != nil {
					t.Fatalf("attempt %d: unexpected error: %v", attempt, err)
				}
				if !bytes.Equal(value, testCase.want) {
					t.Fatalf("attempt %d: pin = %q, want %q", attempt, value, testCase.want)
				}
				zero(value)
			}

			if !bytes.Equal(pin, testCase.pin) {
				t.Errorf("the provider's pin is now %q, want it untouched as %q", pin, testCase.pin)
			}
		})
	}
}

func TestValidateNewPIN(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		pin       []byte
		expectErr bool
	}{
		{name: "six digits", pin: []byte("482913")},
		{name: "a passphrase", pin: []byte("correct horse battery staple")},
		{name: "as long as a sha-256 digest", pin: bytes.Repeat([]byte("a"), 32)},
		{name: "five digits", pin: []byte("48291"), expectErr: true},
		{name: "one digit", pin: []byte("4"), expectErr: true},
		{name: "empty", pin: nil, expectErr: true},
		{name: "longer than the tpm takes", pin: bytes.Repeat([]byte("a"), 33), expectErr: true},
		{name: "six characters outside ascii", pin: []byte("åäöåäö")},
		{name: "three characters in six bytes", pin: []byte("åäö"), expectErr: true},
		{name: "a nul inside", pin: []byte("12\x003456"), expectErr: true},
		{name: "a trailing nul", pin: []byte("123456\x00"), expectErr: true},
		{name: "nuls alone", pin: make([]byte, 6), expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateNewPIN(testCase.pin)
			if (err != nil) != testCase.expectErr {
				t.Fatalf("error = %v, want an error: %v", err, testCase.expectErr)
			}
			if err != nil && !errors.Is(err, altshiftErrors.ErrValidationError) {
				t.Errorf("error %v is not a validation error", err)
			}
		})
	}
}

// TestCreateKeyRefusesShortPIN points CreateKey at a device that is not there, so that a PIN it
// lets through fails at the open, and one it refuses fails before.
func TestCreateKeyRefusesShortPIN(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pin            []byte
		wantValidation bool
	}{
		{name: "a short pin is refused before the tpm is opened", pin: []byte("1234"), wantValidation: true},
		{name: "a long enough pin reaches the device", pin: []byte("482913")},
		{name: "no pin reaches the device", pin: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			absent := filepath.Join(t.TempDir(), "tpmrm0")
			_, err := CreateKey(absent, KeyTypeECCP256, testCase.pin, "test")
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if got := errors.Is(err, altshiftErrors.ErrValidationError); got != testCase.wantValidation {
				t.Errorf("error %v: validation = %v, want %v", err, got, testCase.wantValidation)
			}
		})
	}
}

// srkPublic is a storage root key's public area as CreatePrimary returns it, around a software
// key's point.
func srkPublic(t *testing.T) *tpm2.TPMTPublic {
	t.Helper()

	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x, y := pointCoordinates(t, &software.PublicKey)

	public := tpm2.ECCSRKTemplate
	public.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: x},
		Y: tpm2.TPM2BECCParameter{Buffer: y},
	})

	return &public
}

func TestVerifyParent(t *testing.T) {
	t.Parallel()

	srk := srkPublic(t)
	impostor := srkPublic(t)

	recorded, err := parentName(srk)
	if err != nil {
		t.Fatalf("parent name: %v", err)
	}
	// A TPM name is the name algorithm, then the digest of the public area under it.
	if len(recorded) != 2+sha256.Size || recorded[0] != 0x00 || recorded[1] != byte(tpm2.TPMAlgSHA256) {
		t.Fatalf("name %x is not a SHA-256 TPM name", recorded)
	}

	testCases := []struct {
		name             string
		recorded         []byte
		public           *tpm2.TPMTPublic
		expectErr        bool
		wantVerification bool
	}{
		{name: "the storage root key the key was created under", recorded: recorded, public: srk},
		{
			name:             "an impostor in its place is refused",
			recorded:         recorded,
			public:           impostor,
			expectErr:        true,
			wantVerification: true,
		},
		{name: "a key file with no name recorded is accepted", recorded: nil, public: impostor},
		{name: "no public area to check", recorded: recorded, public: nil, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := verifyParent(testCase.recorded, testCase.public)
			if !testCase.expectErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if got := errors.Is(err, altshiftErrors.ErrVerificationError); got != testCase.wantVerification {
				t.Errorf("error %v: verification = %v, want %v", err, got, testCase.wantVerification)
			}
		})
	}
}

func TestCheckCreated(t *testing.T) {
	t.Parallel()

	software, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template, err := KeyTemplate(KeyTypeRSA2048, false)
	if err != nil {
		t.Fatalf("key template: %v", err)
	}
	eccTemplate, err := KeyTemplate(KeyTypeECCP256, false)
	if err != nil {
		t.Fatalf("key template: %v", err)
	}

	// created is the template as a TPM fills it in, changed by modify.
	created := func(modify func(public *tpm2.TPMTPublic)) *tpm2.TPMTPublic {
		public := *template
		public.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: software.N.Bytes()})
		modify(&public)
		return &public
	}

	testCases := []struct {
		name      string
		template  *tpm2.TPMTPublic
		created   *tpm2.TPMTPublic
		expectErr bool
	}{
		{name: "what was asked for", template: template, created: created(func(*tpm2.TPMTPublic) {})},
		{
			name:      "not fixed to the tpm",
			template:  template,
			created:   created(func(public *tpm2.TPMTPublic) { public.ObjectAttributes.FixedTPM = false }),
			expectErr: true,
		},
		{
			name:      "not fixed to its parent",
			template:  template,
			created:   created(func(public *tpm2.TPMTPublic) { public.ObjectAttributes.FixedParent = false }),
			expectErr: true,
		},
		{
			name:      "sensitive data from outside the tpm",
			template:  template,
			created:   created(func(public *tpm2.TPMTPublic) { public.ObjectAttributes.SensitiveDataOrigin = false }),
			expectErr: true,
		},
		{
			name:      "out from under the lockout",
			template:  template,
			created:   created(func(public *tpm2.TPMTPublic) { public.ObjectAttributes.NoDA = true }),
			expectErr: true,
		},
		{
			name:      "able to decrypt",
			template:  template,
			created:   created(func(public *tpm2.TPMTPublic) { public.ObjectAttributes.Decrypt = true }),
			expectErr: true,
		},
		{
			name:      "another name algorithm",
			template:  template,
			created:   created(func(public *tpm2.TPMTPublic) { public.NameAlg = tpm2.TPMAlgSHA1 }),
			expectErr: true,
		},
		{name: "another type", template: eccTemplate, created: created(func(*tpm2.TPMTPublic) {}), expectErr: true},
		{name: "nothing created", template: template, created: nil, expectErr: true},
		{name: "no template", template: nil, created: created(func(*tpm2.TPMTPublic) {}), expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := checkCreated(testCase.template, testCase.created)
			if (err != nil) != testCase.expectErr {
				t.Fatalf("error = %v, want an error: %v", err, testCase.expectErr)
			}
		})
	}
}

// TestLive exercises the real chip. It is opt in because it generates keys, which takes seconds,
// and because the wrong-PIN case deliberately increments the TPM's dictionary attack counter.
//
//	TPM_SIGNER_LIVE=1 go test ./pkg/signer/ -run TestLive -v
func TestLive(t *testing.T) { //nolint:paralleltest // Drives the real TPM, which is a single shared device.
	if os.Getenv("TPM_SIGNER_LIVE") != "1" {
		t.Skip("set TPM_SIGNER_LIVE=1 to run against the real TPM")
	}

	testCases := []struct {
		name          string
		keyType       KeyType
		pin           []byte
		checkWrongPIN bool
	}{
		{name: "rsa-2048 with pin", keyType: KeyTypeRSA2048, pin: []byte("482913"), checkWrongPIN: true},
		{name: "ecc-p256 with pin", keyType: KeyTypeECCP256, pin: []byte("482913")},
		{name: "ecc-p256 without pin", keyType: KeyTypeECCP256},
	}

	for _, testCase := range testCases { //nolint:paralleltest // Shares the TPM, as above.
		t.Run(testCase.name, func(t *testing.T) {
			start := time.Now()
			created, err := CreateKey(DefaultDevicePath, testCase.keyType, testCase.pin, "test@tpm_signer")
			if err != nil {
				t.Fatalf("create key: %v", err)
			}
			t.Logf("created in %v", time.Since(start).Round(time.Millisecond))

			if len(created.ParentName) == 0 {
				t.Error("the key file records no storage root key name")
			}
			if created.EmptyAuth != (len(testCase.pin) == 0) {
				t.Errorf("EmptyAuth = %v for a key created with a %d-byte PIN", created.EmptyAuth, len(testCase.pin))
			}

			encoded, err := created.Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			key, err := keyfile.Parse(encoded)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](key.Public)
			if err != nil {
				t.Fatalf("unmarshal public: %v", err)
			}
			contents, err := public.Contents()
			if err != nil {
				t.Fatalf("public contents: %v", err)
			}
			if contents.ObjectAttributes.NoDA != key.EmptyAuth {
				t.Errorf("NoDA = %v, want it set exactly when there is no PIN", contents.ObjectAttributes.NoDA)
			}

			var pinProvider PINProvider
			if len(testCase.pin) != 0 {
				pinProvider = func() ([]byte, error) { return bytes.Clone(testCase.pin), nil }
			}

			signer, err := New(key, DefaultDevicePath, pinProvider)
			if err != nil {
				t.Fatalf("new signer: %v", err)
			}

			digest := sha256.Sum256([]byte("hello from the tpm"))

			start = time.Now()
			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			t.Logf("signed in %v", time.Since(start).Round(time.Millisecond))

			switch publicKey := signer.Public().(type) {
			case *rsa.PublicKey:
				if testCase.keyType != KeyTypeRSA2048 {
					t.Fatalf("public key is RSA for a %s key", testCase.keyType)
				}
				if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
					t.Fatalf("signature does not verify: %v", err)
				}
			case *ecdsa.PublicKey:
				if testCase.keyType != KeyTypeECCP256 {
					t.Fatalf("public key is ECDSA for a %s key", testCase.keyType)
				}
				if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
					t.Fatal("signature does not verify")
				}
			default:
				t.Fatalf("unexpected public key type %T", publicKey)
			}

			if !testCase.checkWrongPIN {
				return
			}

			t.Run("wrong pin is refused", func(t *testing.T) { //nolint:paralleltest // Shares the TPM, as above.
				wrong, err := New(key, DefaultDevicePath, func() ([]byte, error) { return []byte("000000"), nil })
				if err != nil {
					t.Fatalf("new signer: %v", err)
				}
				if _, err := wrong.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
					t.Error("a wrong PIN produced a signature")
				}
			})
		})
	}
}
