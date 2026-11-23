package keyfile

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	valid := &Key{
		Description: "test@host",
		Parent:      0x40000001,
		Public:      []byte{0x00, 0x02, 0xaa, 0xbb},
		Private:     []byte{0x00, 0x02, 0xcc, 0xdd},
	}
	validPEM, err := valid.Marshal()
	if err != nil {
		t.Fatalf("fixture marshal: %v", err)
	}
	if validPEM == nil {
		t.Fatal("fixture marshal returned no data")
	}

	testCases := []struct {
		name      string
		data      []byte
		expectErr bool
	}{
		{name: "valid", data: validPEM},
		{name: "empty", data: nil, expectErr: true},
		{name: "not pem", data: []byte("plainly not a key"), expectErr: true},
		{
			name:      "wrong pem type",
			data:      []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
			expectErr: true,
		},
		{
			name:      "pem body is not der",
			data:      []byte("-----BEGIN " + PEMType + "-----\nAAAA\n-----END " + PEMType + "-----\n"),
			expectErr: true,
		},
		{name: "truncated pem body", data: validPEM[:len(validPEM)/2], expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := Parse(testCase.data)
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key.Description != valid.Description {
				t.Errorf("description = %q, want %q", key.Description, valid.Description)
			}
			if key.Parent != valid.Parent {
				t.Errorf("parent = %#x, want %#x", key.Parent, valid.Parent)
			}
			if !bytes.Equal(key.Public, valid.Public) {
				t.Errorf("public = %x, want %x", key.Public, valid.Public)
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		key       *Key
		expectErr bool
	}{
		{
			name: "with pin",
			key:  &Key{Parent: 0x40000001, Public: []byte{0, 1, 2}, Private: []byte{0, 1, 3}},
		},
		{
			name: "empty auth",
			key:  &Key{Parent: 0x40000001, EmptyAuth: true, Public: []byte{0, 1, 2}, Private: []byte{0, 1, 3}},
		},
		{name: "nil key", key: nil, expectErr: true},
		{name: "no public", key: &Key{Parent: 0x40000001, Private: []byte{0, 1}}, expectErr: true},
		{name: "no private", key: &Key{Parent: 0x40000001, Public: []byte{0, 1}}, expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			data, err := testCase.key.Marshal()
			if testCase.expectErr {
				if err == nil {
					t.Fatal("expected an error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			parsed, err := Parse(data)
			if err != nil {
				t.Fatalf("reparse: %v", err)
			}
			if parsed.EmptyAuth != testCase.key.EmptyAuth {
				t.Errorf("emptyAuth = %v, want %v", parsed.EmptyAuth, testCase.key.EmptyAuth)
			}
			if !bytes.Equal(parsed.Private, testCase.key.Private) {
				t.Errorf("private = %x, want %x", parsed.Private, testCase.key.Private)
			}
		})
	}
}

// TestRoundTripAgainstSSHTPMAgent checks this implementation against a key produced by an
// unrelated one. A byte-identical round trip means the ASN.1 here matches the format in the wild.
func TestRoundTripAgainstSSHTPMAgent(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}

	original, err := os.ReadFile(filepath.Join(home, ".ssh", "id_ecdsa.tpm"))
	if err != nil {
		t.Skip("no ssh-tpm-agent key present")
	}

	key, err := Parse(original)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	remarshalled, err := key.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if !bytes.Equal(bytes.TrimSpace(original), bytes.TrimSpace(remarshalled)) {
		t.Error("round trip is not byte identical to ssh-tpm-agent's key file")
	}
}

// legacyContainer is the container as it was before ParentName: what an older build of this
// package parses a key file into.
type legacyContainer struct {
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

func TestParentName(t *testing.T) {
	t.Parallel()

	base := Key{
		Description: "test@host",
		Parent:      0x40000001,
		Public:      []byte{0x00, 0x02, 0xaa, 0xbb},
		Private:     []byte{0x00, 0x02, 0xcc, 0xdd},
	}
	legacyDER, err := asn1.Marshal(legacyContainer{
		Type:        OIDLoadableKey,
		Description: base.Description,
		Parent:      int(base.Parent),
		PubKey:      base.Public,
		PrivKey:     base.Private,
	})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	name := append([]byte{0x00, 0x0b}, bytes.Repeat([]byte{0x5a}, 32)...)

	withName := func(parentName []byte) *Key {
		key := base
		key.ParentName = parentName
		return &key
	}

	testCases := []struct {
		name string
		key  *Key
		// wantLegacy is whether the file must be byte for byte what it was before ParentName.
		wantLegacy bool
		wantName   []byte
	}{
		{name: "no name is the format as it always was", key: withName(nil), wantLegacy: true},
		{name: "an empty name is no name", key: withName([]byte{}), wantLegacy: true},
		{name: "a recorded name survives the round trip", key: withName(name), wantName: name},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := testCase.key.Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			block, _ := pem.Decode(encoded)
			if block == nil {
				t.Fatal("no PEM block")
			}
			if got := bytes.Equal(block.Bytes, legacyDER); got != testCase.wantLegacy {
				t.Errorf("identical to the legacy encoding = %v, want %v", got, testCase.wantLegacy)
			}

			parsed, err := Parse(encoded)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !bytes.Equal(parsed.ParentName, testCase.wantName) {
				t.Errorf("parent name = %x, want %x", parsed.ParentName, testCase.wantName)
			}

			// What an older build makes of the file: it must still load, unchanged in every field
			// it knows.
			var legacy legacyContainer
			if _, err := asn1.Unmarshal(block.Bytes, &legacy); err != nil {
				t.Fatalf("an older build cannot parse the file: %v", err)
			}
			if legacy.Parent != int(base.Parent) || !bytes.Equal(legacy.PubKey, base.Public) ||
				!bytes.Equal(legacy.PrivKey, base.Private) || legacy.Description != base.Description {
				t.Errorf("an older build reads %+v", legacy)
			}
		})
	}
}

// withPolicies is a key file as another tool might write it, with a policy, an authPolicy and a
// secret. The explicit tags are spelt out by hand, since encoding/asn1 writes a RawValue as it
// stands and would drop an explicit tag on the field.
type withPolicies struct {
	Type       asn1.ObjectIdentifier
	Policy     asn1.RawValue
	Secret     asn1.RawValue
	AuthPolicy asn1.RawValue
	Parent     int
	PubKey     []byte
	PrivKey    []byte
}

// TestPoliciesAreDropped pins what the container's comment says: a file with policies parses, and
// marshalling the result writes none of them.
func TestPoliciesAreDropped(t *testing.T) {
	t.Parallel()

	explicit := func(tag int, inner any) asn1.RawValue {
		t.Helper()
		encoded, err := asn1.Marshal(inner)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: encoded}
	}
	// A TPMPolicy is SEQUENCE { commandCode [0] INTEGER, commandPolicy [1] OCTET STRING }; the
	// contents do not matter here, only that there is one.
	type policy struct {
		CommandCode   int    `asn1:"explicit,tag:0"`
		CommandPolicy []byte `asn1:"explicit,tag:1"`
	}
	policies := []policy{{CommandCode: 0x16b, CommandPolicy: []byte{1, 2, 3}}}

	der, err := asn1.Marshal(withPolicies{
		Type:       OIDLoadableKey,
		Policy:     explicit(1, policies),
		Secret:     explicit(2, []byte{9, 9}),
		AuthPolicy: explicit(3, []policy{}),
		Parent:     0x40000001,
		PubKey:     []byte{0x00, 0x02, 0xaa, 0xbb},
		PrivKey:    []byte{0x00, 0x02, 0xcc, 0xdd},
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	var parsed container
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(parsed.Policy.FullBytes) == 0 || len(parsed.Secret) == 0 || len(parsed.AuthPolicy.FullBytes) == 0 {
		t.Fatalf("the fixture's policies were not read as policies: %+v", parsed)
	}
	withoutPolicies, err := (&Key{
		Parent:  0x40000001,
		Public:  []byte{0x00, 0x02, 0xaa, 0xbb},
		Private: []byte{0x00, 0x02, 0xcc, 0xdd},
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	testCases := []struct {
		name string
		data []byte
		want []byte
	}{
		{
			name: "policies parse and are not written back",
			data: pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: der}),
			want: withoutPolicies,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := Parse(testCase.data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			remarshalled, err := key.Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(remarshalled, testCase.want) {
				t.Error("marshalling a parsed key with policies wrote something other than the key without them")
			}
		})
	}
}
