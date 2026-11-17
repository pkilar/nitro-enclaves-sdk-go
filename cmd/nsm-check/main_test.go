package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
