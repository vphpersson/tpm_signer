// Package keyfile implements the TCG "TPM 2.0 Key Files" container: a DER structure wrapped in
// PEM, holding a TPM2B_PUBLIC and a TPM2B_PRIVATE. It is the same format ssh-tpm-agent writes,
// so a key produced here is inspectable with the same tools.
//
// The private component is a blob encrypted to the parent key's seed. It is inert on any TPM
// other than the one that produced it, which is the whole point of the format.
package keyfile

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// PEMType is the PEM block label the format uses.
const PEMType = "TSS2 PRIVATE KEY"

var (
	OIDLoadableKey   = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}
	OIDImportableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 4}
	OIDSealedData    = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 5}
)

// container mirrors the ASN.1 TPMKey SEQUENCE. Policy and AuthPolicy are kept as raw values
// because this package does not implement policy sessions; preserving them means a parse/marshal
// round trip does not silently drop a policy some other tool wrote.
type container struct {
	Type        asn1.ObjectIdentifier
	EmptyAuth   bool          `asn1:"optional,explicit,tag:0"`
	Policy      asn1.RawValue `asn1:"optional,explicit,tag:1"`
	Secret      []byte        `asn1:"optional,explicit,tag:2"`
	AuthPolicy  asn1.RawValue `asn1:"optional,explicit,tag:3"`
	Description string        `asn1:"optional,explicit,tag:4,utf8"`
	RSAParent   bool          `asn1:"optional,explicit,tag:5"`
	Parent      int
	PubKey      []byte
	PrivKey     []byte
}

// Key is a parsed loadable TPM key.
type Key struct {
	// Description is the free-form label the format carries; ssh-tpm-agent puts "user@host" here.
	Description string
	// EmptyAuth reports that the key carries no auth value, meaning anyone who can reach the TPM
	// can make it sign. A PIN-gated key has this false.
	EmptyAuth bool
	// RSAParent selects the RSA SRK template over the ECC one when re-deriving the parent.
	RSAParent bool
	// Parent is the handle the private blob is wrapped under, normally TPM_RH_OWNER.
	Parent uint32
	// Public is a marshalled TPM2B_PUBLIC, size prefix included.
	Public []byte
	// Private is a marshalled TPM2B_PRIVATE, size prefix included.
	Private []byte
}

// Parse reads a PEM-wrapped TPM key.
func Parse(data []byte) (*Key, error) {
	if len(data) == 0 {
		return nil, empty_error.New("data")
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: no PEM block", altshiftErrors.ErrParseError))
	}
	if block.Type != PEMType {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: unexpected PEM type", altshiftErrors.ErrParseError),
			block.Type,
		)
	}

	var parsed container
	rest, err := asn1.Unmarshal(block.Bytes, &parsed)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: asn1 unmarshal: %w", altshiftErrors.ErrParseError, err),
		)
	}
	if len(rest) != 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: trailing data after key", altshiftErrors.ErrParseError),
			len(rest),
		)
	}

	if !parsed.Type.Equal(OIDLoadableKey) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: not a loadable key", altshiftErrors.ErrValidationError),
			parsed.Type.String(),
		)
	}
	if len(parsed.PubKey) == 0 {
		return nil, empty_error.New("pubkey")
	}
	if len(parsed.PrivKey) == 0 {
		return nil, empty_error.New("privkey")
	}
	// A parent handle is a uint32 on the wire. The ASN.1 INTEGER is signed and unbounded, so a
	// hostile file could carry something that does not fit; reject it rather than truncate.
	if parsed.Parent < 0 || parsed.Parent > math.MaxUint32 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: parent handle out of range", altshiftErrors.ErrValidationError),
			parsed.Parent,
		)
	}

	return &Key{
		Description: parsed.Description,
		EmptyAuth:   parsed.EmptyAuth,
		RSAParent:   parsed.RSAParent,
		Parent:      uint32(parsed.Parent),
		Public:      parsed.PubKey,
		Private:     parsed.PrivKey,
	}, nil
}

// Marshal renders a key back to PEM.
func (key *Key) Marshal() ([]byte, error) {
	if key == nil {
		return nil, nil_error.New("key")
	}
	if len(key.Public) == 0 {
		return nil, empty_error.New("public")
	}
	if len(key.Private) == 0 {
		return nil, empty_error.New("private")
	}

	data, err := asn1.Marshal(container{
		Type:        OIDLoadableKey,
		EmptyAuth:   key.EmptyAuth,
		Description: key.Description,
		RSAParent:   key.RSAParent,
		Parent:      int(key.Parent),
		PubKey:      key.Public,
		PrivKey:     key.Private,
	})
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("asn1 marshal: %w", err))
	}

	return pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: data}), nil
}
