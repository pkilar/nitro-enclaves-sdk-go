package nsm

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// The entries of docFixture, each written out by hand from the CBOR rules.
const (
	docModuleID    = "696d6f64756c655f6964" + "63692d31"                               // "module_id": "i-1"
	docDigest      = "66646967657374" + "66534841333834"                               // "digest": "SHA384"
	docTimestamp   = "6974696d657374616d70" + "1b0000018bcfe56800"                     // "timestamp": 1700000000000
	docPCRs        = "6470637273" + "a4" + "0041aa" + "0141bb" + "0241cc" + "181841dd" // "pcrs": {0: h'aa', 1: h'bb', 2: h'cc', 24: h'dd'}
	docCertificate = "6b6365727469666963617465" + "4101"                               // "certificate": h'01'
	docCABundle    = "68636162756e646c65" + "82" + "4102" + "4103"                     // "cabundle": [h'02', h'03']
	docPublicKey   = "6a7075626c69635f6b6579" + "f6"                                   // "public_key": null
	docUserData    = "69757365725f64617461" + "4175"                                   // "user_data": h'75'
	docNonce       = "656e6f6e6365" + "f6"                                             // "nonce": null
)

// docFixture is docFixtureValue encoded: a nine-entry map with the fields in
// declaration order and the PCR indexes ascending.
const docFixture = "a9" + docModuleID + docDigest + docTimestamp + docPCRs + docCertificate + docCABundle +
	docPublicKey + docUserData + docNonce

func docFixtureValue() *AttestationDoc {
	return &AttestationDoc{
		ModuleID:    "i-1",
		Digest:      response.DigestSHA384,
		Timestamp:   1700000000000,
		PCRs:        PCRs{0: {0xaa}, 1: {0xbb}, 2: {0xcc}, 24: {0xdd}},
		Certificate: []byte{0x01},
		CABundle:    [][]byte{{0x02}, {0x03}},
		UserData:    []byte("u"),
	}
}

// Go randomises map iteration, so one run could pass by luck; twenty cannot.
func TestAttestationDoc_MarshalIsDeterministic(t *testing.T) {
	t.Parallel()

	for range 20 {
		got, err := docFixtureValue().Marshal()

		require.NoError(t, err)
		require.Equal(t, docFixture, hex.EncodeToString(got))
	}
}

func TestPCRs_NilEncodesAsEmptyMap(t *testing.T) {
	t.Parallel()

	got, err := PCRs(nil).MarshalCBOR()

	require.NoError(t, err)
	assert.Equal(t, []byte{0xa0}, got)
}

func TestParseAttestationDoc(t *testing.T) {
	t.Parallel()

	// The same document with its PCRs listed as 24, 2, 1, 0.
	unsortedPCRs := strings.Replace(docFixture,
		"0041aa"+"0141bb"+"0241cc"+"181841dd",
		"181841dd"+"0241cc"+"0141bb"+"0041aa", 1)
	// The same document with a tenth entry, "new": true.
	unknownField := "aa" + docFixture[2:] + "636e6577" + "f5"

	tests := []struct {
		name    string
		payload string
	}{
		{name: "fixture", payload: docFixture},
		{name: "PCRs in any order", payload: unsortedPCRs},
		{name: "unknown field is ignored", payload: unknownField},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAttestationDoc(fromHex(t, tt.payload))

			require.NoError(t, err)
			assert.Equal(t, docFixtureValue(), got)
		})
	}
}

func TestParseAttestationDoc_RejectsMalformedPayloads(t *testing.T) {
	t.Parallel()

	// Each of these is the valid fixture with a tenth entry added, so that
	// entry is the only reason to refuse the document.
	withEntry := func(entry string) string { return "aa" + docFixture[2:] + entry }
	// "module_id" a second time.
	duplicateKey := withEntry(docModuleID)
	// The limits apply to entries the decoder skips too, so these add one the
	// document does not have.
	// "extra": [[[[[1]]]]], five arrays deep inside the map.
	tooDeep := withEntry("656578747261" + "8181818181" + "01")
	// "extra": [0, 0, ... 65 times]
	tooManyElements := withEntry("656578747261" + "9841" + strings.Repeat("00", 65))
	// "extra": {0: 0, 1: 0, ... 65 pairs}
	var pairs strings.Builder
	for key := range 65 {
		if key < 24 {
			fmt.Fprintf(&pairs, "%02x00", key)
		} else {
			fmt.Fprintf(&pairs, "18%02x00", key)
		}
	}
	tooManyPairs := withEntry("656578747261" + "b841" + pairs.String())

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "not a map", payload: fromHex(t, "01")},
		{name: "empty map", payload: fromHex(t, "a0")},
		// "digest": "SHA1"
		{name: "unknown digest", payload: fromHex(t, strings.Replace(docFixture,
			docDigest, "66646967657374"+"6453484131", 1))},
		{name: "truncated", payload: fromHex(t, docFixture[:len(docFixture)-4])},
		{name: "trailing bytes", payload: fromHex(t, docFixture+"00")},
		{name: "duplicate key", payload: fromHex(t, duplicateKey)},
		{name: "nested too deeply", payload: fromHex(t, tooDeep)},
		{name: "array with too many elements", payload: fromHex(t, tooManyElements)},
		{name: "map with too many pairs", payload: fromHex(t, tooManyPairs)},
		{name: "wrong field type", payload: fromHex(t, "a1"+"696d6f64756c655f6964"+"01")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAttestationDoc(tt.payload)

			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

// The payload here is a valid document, so only its size can be the reason it
// is refused.
func TestParseAttestationDoc_RejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	doc := docFixtureValue()
	doc.UserData = make([]byte, MaxResponseSize)
	payload, err := doc.Marshal()
	require.NoError(t, err)

	got, err := ParseAttestationDoc(payload)

	require.Error(t, err)
	assert.Nil(t, got)
}

func TestParseAttestationDoc_AcceptsDocumentWithoutOptionalFields(t *testing.T) {
	t.Parallel()

	payload := "a6" + docModuleID + docDigest + docTimestamp + docPCRs + docCertificate + docCABundle
	want := docFixtureValue()
	want.UserData = nil

	got, err := ParseAttestationDoc(fromHex(t, payload))

	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// Six fields are mandatory. A document that lacks one, has null in its place,
// or spells its name in another case is not an attestation document.
func TestParseAttestationDoc_RequiresMandatoryFields(t *testing.T) {
	t.Parallel()

	optional := docPublicKey + docUserData + docNonce
	mandatory := []struct {
		name  string
		entry string
	}{
		{name: "module_id", entry: docModuleID},
		{name: "digest", entry: docDigest},
		{name: "timestamp", entry: docTimestamp},
		{name: "pcrs", entry: docPCRs},
		{name: "certificate", entry: docCertificate},
		{name: "cabundle", entry: docCABundle},
	}

	for i, field := range mandatory {
		t.Run(field.name+" missing", func(t *testing.T) {
			var others strings.Builder
			for j, other := range mandatory {
				if j != i {
					others.WriteString(other.entry)
				}
			}

			got, err := ParseAttestationDoc(fromHex(t, "a8"+others.String()+optional))

			require.ErrorContains(t, err, field.name)
			assert.Nil(t, got)
		})
	}

	t.Run("module_id null", func(t *testing.T) {
		// "module_id": null
		payload := strings.Replace(docFixture, docModuleID, "696d6f64756c655f6964"+"f6", 1)

		got, err := ParseAttestationDoc(fromHex(t, payload))

		require.ErrorContains(t, err, "module_id")
		assert.Nil(t, got)
	})
	t.Run("module_id in upper case", func(t *testing.T) {
		// "MODULE_ID": "i-1"
		payload := strings.Replace(docFixture, docModuleID, "694d4f44554c455f4944"+"63692d31", 1)

		got, err := ParseAttestationDoc(fromHex(t, payload))

		require.ErrorContains(t, err, "module_id")
		assert.Nil(t, got)
	})
}

// Names match exactly, as they do for serde, so an entry spelled in another
// case is an unknown one and is skipped.
func TestParseAttestationDoc_IgnoresOptionalFieldInAnotherCase(t *testing.T) {
	t.Parallel()

	// "USER_DATA": h'75'
	payload := strings.Replace(docFixture, docUserData, "69555345525f44415441"+"4175", 1)
	want := docFixtureValue()
	want.UserData = nil

	got, err := ParseAttestationDoc(fromHex(t, payload))

	require.NoError(t, err)
	assert.Equal(t, want, got)
}
