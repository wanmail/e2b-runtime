package egresstunnel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestID(t *testing.T) {
	t.Parallel()

	got, err := ID("e2b.local", "team-1", "sbx-2", "exec-3")
	require.NoError(t, err)
	assert.Equal(t, "spiffe://e2b.local/ns/team-1/sbx/sbx-2/exec/exec-3", got)
}

func TestIDRejectsEmptyOrIllegal(t *testing.T) {
	t.Parallel()

	_, err := ID("", "t", "s", "e")
	require.Error(t, err)

	_, err = ID("e2b.local", "", "s", "e")
	require.Error(t, err)

	_, err = ID("e2b.local", "t/a", "s", "e")
	require.Error(t, err)
}
