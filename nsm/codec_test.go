package nsm

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// fromHex decodes a hex fixture. The fixtures in this file were written out by
// hand from the CBOR rules (RFC 8949), not produced by the encoder under test.
func fromHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	require.NoError(t, err)

	return b
}

func TestEncodeRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  request.Request
		want string
	}{
		{
			// {"DescribePCR": {"index": 3}}
			name: "DescribePCR",
			req:  &request.DescribePCR{Index: 3},
			want: "a1" + "6b4465736372696265504352" + "a1" + "65696e646578" + "03",
		},
		{
			// {"ExtendPCR": {"index": 16, "data": h'abcd'}}
			name: "ExtendPCR",
			req:  &request.ExtendPCR{Index: 16, Data: []byte{0xab, 0xcd}},
			want: "a1" + "69457874656e64504352" + "a2" + "65696e646578" + "10" + "6464617461" + "42abcd",
		},
		{
			// {"LockPCR": {"index": 16}}
			name: "LockPCR",
			req:  &request.LockPCR{Index: 16},
			want: "a1" + "674c6f636b504352" + "a1" + "65696e646578" + "10",
		},
		{
			// {"LockPCRs": {"range": 32}}
			name: "LockPCRs",
			req:  &request.LockPCRs{Range: 32},
			want: "a1" + "684c6f636b50435273" + "a1" + "6572616e6765" + "1820",
		},
		{
			// "DescribeNSM"
			name: "DescribeNSM",
			req:  &request.DescribeNSM{},
			want: "6b44657363726962654e534d",
		},
		{
			// {"Attestation": {"user_data": null, "nonce": null, "public_key": null}}
			name: "Attestation without optional fields",
			req:  &request.Attestation{},
			want: "a1" + "6b4174746573746174696f6e" + "a3" +
				"69757365725f64617461" + "f6" +
				"656e6f6e6365" + "f6" +
				"6a7075626c69635f6b6579" + "f6",
		},
		{
			// {"Attestation": {"user_data": h'75', "nonce": h'6e', "public_key": h'706b'}}
			name: "Attestation with every field",
			req:  &request.Attestation{UserData: []byte("u"), Nonce: []byte("n"), PublicKey: []byte("pk")},
			want: "a1" + "6b4174746573746174696f6e" + "a3" +
				"69757365725f64617461" + "4175" +
				"656e6f6e6365" + "416e" +
				"6a7075626c69635f6b6579" + "42706b",
		},
		{
			// "GetRandom"
			name: "GetRandom",
			req:  &request.GetRandom{},
			want: "6947657452616e646f6d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeRequest(tt.req)

			require.NoError(t, err)
			assert.Equal(t, tt.want, hex.EncodeToString(got))
		})
	}
}

func TestDecodeResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want response.Response
	}{
		{
			// {"DescribePCR": {"lock": true, "data": h'aabb'}}
			name: "DescribePCR",
			data: "a1" + "6b4465736372696265504352" + "a2" + "646c6f636b" + "f5" + "6464617461" + "42aabb",
			want: response.Response{DescribePCR: &response.DescribePCR{Lock: true, Data: []byte{0xaa, 0xbb}}},
		},
		{
			// {"ExtendPCR": {"data": h'cc'}}
			name: "ExtendPCR",
			data: "a1" + "69457874656e64504352" + "a1" + "6464617461" + "41cc",
			want: response.Response{ExtendPCR: &response.ExtendPCR{Data: []byte{0xcc}}},
		},
		{
			// "LockPCR"
			name: "LockPCR",
			data: "674c6f636b504352",
			want: response.Response{LockPCR: &response.LockPCR{}},
		},
		{
			// "LockPCRs"
			name: "LockPCRs",
			data: "684c6f636b50435273",
			want: response.Response{LockPCRs: &response.LockPCRs{}},
		},
		{
			// {"DescribeNSM": {"version_major": 1, "version_minor": 0, "version_patch": 0,
			//   "module_id": "i-1", "max_pcrs": 32, "locked_pcrs": [0, 1], "digest": "SHA384"}}
			name: "DescribeNSM",
			data: "a1" + "6b44657363726962654e534d" + "a7" +
				"6d76657273696f6e5f6d616a6f72" + "01" +
				"6d76657273696f6e5f6d696e6f72" + "00" +
				"6d76657273696f6e5f7061746368" + "00" +
				"696d6f64756c655f6964" + "63692d31" +
				"686d61785f70637273" + "1820" +
				"6b6c6f636b65645f70637273" + "820001" +
				"66646967657374" + "66534841333834",
			want: response.Response{DescribeNSM: &response.DescribeNSM{
				VersionMajor: 1,
				ModuleID:     "i-1",
				MaxPCRs:      32,
				LockedPCRs:   []uint16{0, 1},
				Digest:       response.DigestSHA384,
			}},
		},
		{
			// {"Attestation": {"document": h'0102'}}
			name: "Attestation",
			data: "a1" + "6b4174746573746174696f6e" + "a1" + "68646f63756d656e74" + "420102",
			want: response.Response{Attestation: &response.Attestation{Document: []byte{0x01, 0x02}}},
		},
		{
			// {"GetRandom": {"random": h'0a0b0c'}}
			name: "GetRandom",
			data: "a1" + "6947657452616e646f6d" + "a1" + "6672616e646f6d" + "430a0b0c",
			want: response.Response{GetRandom: &response.GetRandom{Random: []byte{0x0a, 0x0b, 0x0c}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeResponse(fromHex(t, tt.data))

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDecodeResponse_ReturnsErrorCodeAsError(t *testing.T) {
	t.Parallel()

	// {"Error": "InvalidIndex"}
	data := fromHex(t, "a1"+"654572726f72"+"6c496e76616c6964496e646578")

	got, err := decodeResponse(data)

	var nsmErr *Error
	require.ErrorAs(t, err, &nsmErr)
	assert.Equal(t, response.ECInvalidIndex, nsmErr.Code)
	assert.Equal(t, response.Response{}, got)
}

func TestDecodeResponse_RejectsMalformedReplies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "empty reply", data: ""},
		// {"GetRandom": {"random": h'01'}, "ExtendPCR": {"data": h'02'}}
		{name: "two replies in one map", data: "a2" + "6947657452616e646f6d" + "a1" + "6672616e646f6d" + "4101" +
			"69457874656e64504352" + "a1" + "6464617461" + "4102"},
		// {"Error": "InternalError", "GetRandom": {"random": h'01'}}
		{name: "error code together with a reply", data: "a2" + "654572726f72" + "6d496e7465726e616c4572726f72" +
			"6947657452616e646f6d" + "a1" + "6672616e646f6d" + "4101"},
		// {"GetRandom": {"random": h'01'}, "GetRandom": {"random": h'02'}}
		{name: "same reply twice", data: "a2" + "6947657452616e646f6d" + "a1" + "6672616e646f6d" + "4101" +
			"6947657452616e646f6d" + "a1" + "6672616e646f6d" + "4102"},
		// {"getrandom": {"random": h'01'}}
		{name: "reply name in the wrong case", data: "a1" + "6967657472616e646f6d" + "a1" + "6672616e646f6d" + "4101"},
		// {"GetRandom": {"RANDOM": h'01'}}
		{name: "field name in the wrong case", data: "a1" + "6947657452616e646f6d" + "a1" + "6652414e444f4d" + "4101"},
		{name: "unknown bare name", data: "65426f677573"},                                    // "Bogus"
		{name: "map without a known reply", data: "a0"},                                      // {}
		{name: "map with an unknown reply", data: "a165426f677573a0"},                        // {"Bogus": {}}
		{name: "neither text nor map", data: "01"},                                           // 1
		{name: "truncated text", data: "674c6f636b"},                                         // "LockPCR" cut short
		{name: "trailing bytes", data: "674c6f636b50435200"},                                 // "LockPCR" then 0
		{name: "wrong field type", data: "a16b4174746573746174696f6ea168646f63756d656e7401"}, // document: 1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeResponse(fromHex(t, tt.data))

			require.Error(t, err)
			var nsmErr *Error
			assert.NotErrorAs(t, err, &nsmErr, "a malformed reply is not an NSM refusal")
			assert.Equal(t, response.Response{}, got)
		})
	}
}

func TestError_MessageNamesTheCode(t *testing.T) {
	t.Parallel()

	err := &Error{Code: response.ECReadOnlyIndex}

	assert.ErrorContains(t, err, "ReadOnlyIndex")
}

func TestDigestSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		digest response.Digest
		want   int
	}{
		{digest: response.DigestSHA256, want: 32},
		{digest: response.DigestSHA384, want: 48},
		{digest: response.DigestSHA512, want: 64},
		{digest: "SHA1", want: 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.digest), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.digest.Size())
		})
	}
}
