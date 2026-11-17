package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pkilar/nitro-enclaves-sdk-go/internal/nsmtest"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm"
	"github.com/pkilar/nitro-enclaves-sdk-go/nsm/response"
)

// openFake returns an opener for a session on device, in place of nsm.Open.
func openFake(device *nsmtest.Device) func() (*nsm.Session, error) {
	return func() (*nsm.Session, error) {
		return nsm.NewSession(device), nil
	}
}

func TestRun_ReportsSuccessOnTheLastLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantChecks int
	}{
		{name: "the checks that only read", wantChecks: 5},
		{name: "with the checks that write PCRs", args: []string{"-pcr-writes"}, wantChecks: 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			device := nsmtest.NewDevice()
			var stdout, stderr bytes.Buffer

			code := runWith(openFake(device), tt.args, &stdout, &stderr)

			assert.Equal(t, 0, code)
			assert.Empty(t, stderr.String())

			lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
			require.Len(t, lines, tt.wantChecks+1, "one line per check, then the verdict")
			for _, line := range lines[:tt.wantChecks] {
				assert.Regexp(t, `^ok    \S`, line)
			}
			assert.Equal(t, "nsm-check: all checks passed", lines[tt.wantChecks])
			assert.True(t, device.Closed(), "the session is closed")
		})
	}
}

func TestRun_DoesNotReportSuccessWhenACheckFails(t *testing.T) {
	t.Parallel()

	device := nsmtest.NewDevice()
	device.RefuseWith(response.ECInternalError)
	var stdout, stderr bytes.Buffer

	code := runWith(openFake(device), nil, &stdout, &stderr)

	assert.Equal(t, 1, code)
	assert.NotContains(t, stdout.String(), "all checks passed")
	assert.Contains(t, stdout.String(), "FAIL  NSM description: ")
	assert.Contains(t, stderr.String(), "nsm-check: NSM description: ")
	assert.Contains(t, stderr.String(), string(response.ECInternalError))
	assert.True(t, device.Closed(), "the session is closed")
}

func TestRun_RejectsUnknownFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	code := run([]string{"-no-such-flag"}, &stdout, &stderr)

	assert.Equal(t, 2, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "-pcr-writes", "usage names the flag that does exist")
}

func TestRun_HelpExitsCleanly(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	code := run([]string{"-h"}, &stdout, &stderr)

	assert.Equal(t, 0, code)
	assert.Contains(t, stderr.String(), "-pcr-writes")
}

func TestRun_FailsWhereThereIsNoNSM(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat("/dev/nsm"); err == nil {
		t.Skip("the NSM device exists here")
	}

	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)

	assert.Equal(t, 1, code)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "nsm-check: nsm: open device")
}
