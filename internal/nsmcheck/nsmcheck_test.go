package nsmcheck

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/internal/nsmtest"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/request"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

const (
	readOnlyOutput = "ok    NSM description\n" +
		"ok    PCR lengths\n" +
		"ok    initial PCR state\n" +
		"ok    attestation\n" +
		"ok    random bytes\n"
	pcrWritesOutput = readOnlyOutput +
		"ok    reserved PCRs cannot be locked\n" +
		"ok    extending and locking PCRs\n" +
		"ok    locking PCR ranges\n" +
		"ok    locked PCRs are read-only\n"
)

// newSession returns a session on device that is closed when the test ends.
func newSession(t *testing.T, device nsm.Device) *nsm.Session {
	t.Helper()

	session := nsm.NewSession(device)
	t.Cleanup(func() { require.NoError(t, session.Close()) })

	return session
}

// encode returns the CBOR encoding of v.
func encode(t *testing.T, v any) []byte {
	t.Helper()

	encoded, err := cbor.Marshal(v)
	require.NoError(t, err)

	return encoded
}

// decodeHex decodes a hex fixture written out by hand.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(s)
	require.NoError(t, err)

	return decoded
}

func TestRun_ReadOnlyChecksPassAndLeaveTheNSMUntouched(t *testing.T) {
	t.Parallel()

	session := newSession(t, nsmtest.NewDevice())
	var out bytes.Buffer

	err := Run(session, &out, Options{})

	require.NoError(t, err)
	assert.Equal(t, readOnlyOutput, out.String())
	res, err := session.Send(&request.DescribePCR{Index: 16})
	require.NoError(t, err)
	require.NotNil(t, res.DescribePCR)
	assert.Equal(t, response.DescribePCR{Data: make([]byte, 48)}, *res.DescribePCR)
}

func TestRun_PCRWriteChecksPassAndLockEveryPCR(t *testing.T) {
	t.Parallel()

	session := newSession(t, nsmtest.NewDevice())
	var out bytes.Buffer

	err := Run(session, &out, Options{PCRWrites: true})

	require.NoError(t, err)
	assert.Equal(t, pcrWritesOutput, out.String())
	res, err := session.Send(&request.DescribeNSM{})
	require.NoError(t, err)
	require.NotNil(t, res.DescribeNSM)
	assert.Len(t, res.DescribeNSM.LockedPCRs, 32)
}

func TestRun_FailsOnAnEnclaveWhosePCRsWereAlreadyWritten(t *testing.T) {
	t.Parallel()

	session := newSession(t, nsmtest.NewDevice())
	require.NoError(t, Run(session, &bytes.Buffer{}, Options{PCRWrites: true}))
	var out bytes.Buffer

	err := Run(session, &out, Options{})

	require.ErrorContains(t, err, "initial PCR state")
	assert.Equal(t, "ok    NSM description\nok    PCR lengths\nFAIL  initial PCR state: "+
		"locked PCRs are [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31], "+
		"want [0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15]\n", out.String())
}

func TestRun_StopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()

	device := nsmtest.NewDevice()
	device.RefuseWith(response.ECInternalError)
	var out bytes.Buffer

	err := Run(newSession(t, device), &out, Options{PCRWrites: true})

	var nsmErr *nsm.Error
	require.ErrorAs(t, err, &nsmErr)
	assert.Equal(t, response.ECInternalError, nsmErr.Code)
	assert.Equal(t, 1, strings.Count(out.String(), "\n"), "one line of output")
	assert.True(t, strings.HasPrefix(out.String(), "FAIL  NSM description: "), "output is %q", out.String())
}

// misbehavingNSM wraps a simulated NSM and lets a test change what it is
// asked or what it answers, to show that each check notices.
type misbehavingNSM struct {
	*nsmtest.Device
	// rewrite, when set, replaces a request before the NSM sees it.
	rewrite func(req []byte) []byte
	// answer, when set, may return a reply to send without asking the NSM;
	// nil means ask it.
	answer func(req []byte) []byte
}

func (d *misbehavingNSM) Exchange(req, res []byte) (int, error) {
	if d.answer != nil {
		if canned := d.answer(req); canned != nil {
			return copy(res, canned), nil
		}
	}
	if d.rewrite != nil {
		req = d.rewrite(req)
	}

	return d.Device.Exchange(req, res)
}

// requestName returns the name of the request variant in req.
func requestName(t *testing.T, req []byte) string {
	t.Helper()

	var decoded any
	require.NoError(t, cbor.Unmarshal(req, &decoded))
	switch v := decoded.(type) {
	case string:
		return v
	case map[any]any:
		for key := range v {
			name, ok := key.(string)
			require.True(t, ok, "request key has type %T, want string", key)
			return name
		}
	}
	require.Fail(t, "request is neither a name nor a map", "%x", req)

	return ""
}

func TestRun_NoticesAMisbehavingNSM(t *testing.T) {
	t.Parallel()

	describeWith := func(change func(*response.DescribeNSM)) func(*testing.T) *misbehavingNSM {
		return func(t *testing.T) *misbehavingNSM {
			desc := response.DescribeNSM{
				VersionMajor: 1,
				ModuleID:     nsmtest.ModuleID,
				MaxPCRs:      nsmtest.MaxPCRs,
				LockedPCRs:   []uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				Digest:       response.DigestSHA384,
			}
			change(&desc)
			reply := encode(t, map[string]response.DescribeNSM{"DescribeNSM": desc})

			return &misbehavingNSM{Device: nsmtest.NewDevice(), answer: func(req []byte) []byte {
				if requestName(t, req) == "DescribeNSM" {
					return reply
				}
				return nil
			}}
		}
	}
	answerTo := func(name string, reply any) func(*testing.T) *misbehavingNSM {
		return func(t *testing.T) *misbehavingNSM {
			encoded := encode(t, reply)

			return &misbehavingNSM{Device: nsmtest.NewDevice(), answer: func(req []byte) []byte {
				if requestName(t, req) == name {
					return encoded
				}
				return nil
			}}
		}
	}

	tests := []struct {
		name      string
		device    func(*testing.T) *misbehavingNSM
		pcrWrites bool
		wantCheck string
	}{
		{
			name:      "unknown digest",
			device:    describeWith(func(d *response.DescribeNSM) { d.Digest = "SHA1" }),
			wantCheck: "NSM description",
		},
		{
			name:      "too few PCRs",
			device:    describeWith(func(d *response.DescribeNSM) { d.MaxPCRs = 8 }),
			wantCheck: "NSM description",
		},
		{
			name:      "no module ID",
			device:    describeWith(func(d *response.DescribeNSM) { d.ModuleID = "" }),
			wantCheck: "NSM description",
		},
		{
			name: "PCR of the wrong length",
			device: answerTo("DescribePCR", map[string]response.DescribePCR{
				"DescribePCR": {Lock: true, Data: make([]byte, 32)},
			}),
			wantCheck: "PCR lengths",
		},
		{
			name:      "reserved PCR listed as unlocked",
			device:    describeWith(func(d *response.DescribeNSM) { d.LockedPCRs = d.LockedPCRs[:15] }),
			wantCheck: "initial PCR state",
		},
		{
			name: "free PCR reported as locked",
			device: answerTo("DescribePCR", map[string]response.DescribePCR{
				"DescribePCR": {Lock: true, Data: make([]byte, 48)},
			}),
			wantCheck: "initial PCR state",
		},
		{
			name: "free PCR that is not zero",
			device: func(t *testing.T) *misbehavingNSM {
				device := nsmtest.NewDevice()
				session := nsm.NewSession(device)
				_, err := session.Send(&request.ExtendPCR{Index: 20, Data: []byte("used")})
				require.NoError(t, err)

				return &misbehavingNSM{Device: device}
			},
			wantCheck: "initial PCR state",
		},
		{
			name: "attestation that drops the request's data",
			device: func(t *testing.T) *misbehavingNSM {
				empty := encode(t, (&request.Attestation{}).Encoded())

				return &misbehavingNSM{Device: nsmtest.NewDevice(), rewrite: func(req []byte) []byte {
					if requestName(t, req) == "Attestation" {
						return empty
					}
					return req
				}}
			},
			wantCheck: "attestation",
		},
		{
			name: "attestation document that is not an envelope",
			device: answerTo("Attestation", map[string]response.Attestation{
				"Attestation": {Document: []byte("not CBOR")},
			}),
			wantCheck: "attestation",
		},
		{
			name: "random bytes that repeat",
			device: answerTo("GetRandom", map[string]response.GetRandom{
				"GetRandom": {Random: []byte{1, 2, 3, 4}},
			}),
			wantCheck: "random bytes",
		},
		{
			name:      "reserved PCR that can be locked",
			device:    answerTo("LockPCR", "LockPCR"),
			pcrWrites: true,
			wantCheck: "reserved PCRs cannot be locked",
		},
		{
			name: "extend that does not change the PCR",
			device: answerTo("ExtendPCR", map[string]response.ExtendPCR{
				"ExtendPCR": {Data: bytes.Repeat([]byte{7}, 48)},
			}),
			pcrWrites: true,
			wantCheck: "extending and locking PCRs",
		},
		{
			name:      "range past the last PCR that can be locked",
			device:    answerTo("LockPCRs", "LockPCRs"),
			pcrWrites: true,
			wantCheck: "locking PCR ranges",
		},
		{
			name: "wrong kind of reply to locking a reserved PCR",
			device: func(t *testing.T) *misbehavingNSM {
				wrong := encode(t, "LockPCRs")

				return &misbehavingNSM{Device: nsmtest.NewDevice(), answer: func(req []byte) []byte {
					var lock map[string]request.LockPCR
					if requestName(t, req) != "LockPCR" || cbor.Unmarshal(req, &lock) != nil {
						return nil
					}
					if lock["LockPCR"].Index >= nsmtest.ReservedPCRs {
						return nil
					}

					return wrong
				}}
			},
			pcrWrites: true,
			wantCheck: "reserved PCRs cannot be locked",
		},
		{
			name: "wrong kind of reply to locking a range past the last PCR",
			device: func(t *testing.T) *misbehavingNSM {
				wrong := encode(t, "LockPCR")

				return &misbehavingNSM{Device: nsmtest.NewDevice(), answer: func(req []byte) []byte {
					var lock map[string]request.LockPCRs
					if requestName(t, req) != "LockPCRs" || cbor.Unmarshal(req, &lock) != nil {
						return nil
					}
					if lock["LockPCRs"].Range <= nsmtest.MaxPCRs {
						return nil
					}

					return wrong
				}}
			},
			pcrWrites: true,
			wantCheck: "locking PCR ranges",
		},
		{
			name: "wrong kind of reply to extending a locked PCR",
			device: func(t *testing.T) *misbehavingNSM {
				wrong := encode(t, "LockPCR")
				// The first extends are of the free PCRs, extendRounds times
				// each. Every extend after those is of a locked PCR.
				extendsOfFreePCRs := (nsmtest.MaxPCRs - nsmtest.ReservedPCRs) * extendRounds
				extends := 0

				return &misbehavingNSM{Device: nsmtest.NewDevice(), answer: func(req []byte) []byte {
					if requestName(t, req) != "ExtendPCR" {
						return nil
					}
					extends++
					if extends <= extendsOfFreePCRs {
						return nil
					}

					return wrong
				}}
			},
			pcrWrites: true,
			wantCheck: "locked PCRs are read-only",
		},
		{
			name: "locked PCR that can still be extended",
			device: func(t *testing.T) *misbehavingNSM {
				var extensions byte

				return &misbehavingNSM{Device: nsmtest.NewDevice(), answer: func(req []byte) []byte {
					if requestName(t, req) != "ExtendPCR" {
						return nil
					}
					extensions++

					return encode(t, map[string]response.ExtendPCR{
						"ExtendPCR": {Data: bytes.Repeat([]byte{extensions}, 48)},
					})
				}}
			},
			pcrWrites: true,
			wantCheck: "locked PCRs are read-only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer

			err := Run(newSession(t, tt.device(t)), &out, Options{PCRWrites: tt.pcrWrites})

			require.ErrorContains(t, err, tt.wantCheck)
			lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
			assert.True(t, strings.HasPrefix(lines[len(lines)-1], "FAIL  "+tt.wantCheck+": "),
				"last line is %q", lines[len(lines)-1])
		})
	}
}

func TestPayloadOf(t *testing.T) {
	t.Parallel()

	// [h'a0', {}, h'7061796c6f6164', h'736967']: "payload" signed by "sig".
	const untagged = "84" + "41a0" + "a0" + "477061796c6f6164" + "43736967"

	tests := []struct {
		name     string
		document string
	}{
		{name: "untagged envelope", document: untagged},
		{name: "envelope under tag 18", document: "d2" + untagged},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := payloadOf(decodeHex(t, tt.document))

			require.NoError(t, err)
			assert.Equal(t, []byte("payload"), got)
		})
	}
}

func TestPayloadOf_RejectsWhatIsNotAnEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
	}{
		{name: "empty", document: ""},
		{name: "not an array", document: "a0"},
		{name: "three elements", document: "83" + "41a0" + "a0" + "477061796c6f6164"},
		{name: "empty payload", document: "84" + "41a0" + "a0" + "40" + "43736967"},
		{name: "payload that is not bytes", document: "84" + "41a0" + "a0" + "01" + "43736967"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := payloadOf(decodeHex(t, tt.document))

			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

// A check that expects the NSM to say no must not be satisfied by a failure of
// some other kind.
func TestRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		// wantRefusal is whether err shows the NSM refusing the request.
		wantRefusal bool
	}{
		{name: "NSM answers ReadOnlyIndex", err: &nsm.Error{Code: response.ECReadOnlyIndex}, wantRefusal: true},
		{
			name:        "NSM answers InvalidIndex, wrapped",
			err:         fmt.Errorf("lock PCR 3: %w", &nsm.Error{Code: response.ECInvalidIndex}),
			wantRefusal: true,
		},
		{name: "request succeeded", err: nil},
		{name: "reply of the wrong kind", err: &nsm.Error{Code: response.ECInvalidResponse}},
		{name: "error reply that says Success", err: &nsm.Error{Code: response.ECSuccess}},
		{name: "device call failed", err: &nsm.IoctlError{Errno: syscall.EIO}},
		{name: "reply could not be decoded", err: errors.New("nsm: decode response: unknown reply")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := refused(tt.err)

			if tt.wantRefusal {
				require.NoError(t, got)
				return
			}
			require.Error(t, got)
		})
	}
}
