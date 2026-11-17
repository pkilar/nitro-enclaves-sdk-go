//go:build !(linux && (amd64 || arm64))

package nsm

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen_ReportsUnsupportedPlatform(t *testing.T) {
	t.Parallel()

	session, err := Open()

	require.ErrorIs(t, err, errors.ErrUnsupported)
	assert.Nil(t, session)
}
