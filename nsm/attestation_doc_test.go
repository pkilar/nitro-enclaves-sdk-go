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

// docFixture is docFixtureValue encoded by hand from the CBOR rules: a
// nine-entry map with the fields in declaration order and the PCR indexes
// ascending.
const docFixture = "a9" +
	"696d6f64756c655f6964" + "63692d31" + // "module_id": "i-1"
	"66646967657374" + "66534841333834" + // "digest": "SHA384"
	"6974696d657374616d70" + "1b0000018bcfe56800" + // "timestamp": 1700000000000
	"6470637273" + "a4" + "0041aa" + "0141bb" + "0241cc" + "181841dd" + // "pcrs": {0: h'aa', 1: h'bb', 2: h'cc', 24: h'dd'}
	"6b6365727469666963617465" + "4101" + // "certificate": h'01'
	"68636162756e646c65" + "82" + "4102" + "4103" + // "cabundle": [h'02', h'03']
	"6a7075626c69635f6b6579" + "f6" + // "public_key": null
	"69757365725f64617461" + "4175" + // "user_data": h'75'
	"656e6f6e6365" + "f6" // "nonce": null

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

	// {"module_id": "a", "module_id": "b"}
	duplicateKey := "a2" + "696d6f64756c655f6964" + "6161" + "696d6f64756c655f6964" + "6162"
	// The limits apply to fields the decoder skips too, so these use a field
	// the document does not have.
	// {"extra": [[[[[1]]]]]}: five arrays deep inside the map.
	tooDeep := "a1" + "656578747261" + "8181818181" + "01"
	// {"extra": [0, 0, ... 65 times]}
	tooManyElements := "a1" + "656578747261" + "9841" + strings.Repeat("00", 65)
	// {"extra": {0: 0, 1: 0, ... 65 pairs}}
	var tooManyPairs strings.Builder
	tooManyPairs.WriteString("a1" + "656578747261" + "b841")
	for key := range 65 {
		if key < 24 {
			fmt.Fprintf(&tooManyPairs, "%02x00", key)
		} else {
			fmt.Fprintf(&tooManyPairs, "18%02x00", key)
		}
	}

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "not a map", payload: fromHex(t, "01")},
		{name: "truncated", payload: fromHex(t, docFixture[:len(docFixture)-4])},
		{name: "trailing bytes", payload: fromHex(t, docFixture+"00")},
		{name: "duplicate key", payload: fromHex(t, duplicateKey)},
		{name: "nested too deeply", payload: fromHex(t, tooDeep)},
		{name: "array with too many elements", payload: fromHex(t, tooManyElements)},
		{name: "map with too many pairs", payload: fromHex(t, tooManyPairs.String())},
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
