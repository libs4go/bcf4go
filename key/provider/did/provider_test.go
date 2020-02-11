package eth

import (
	"testing"

	"github.com/libs4go/bcf4go/key"
	_ "github.com/libs4go/bcf4go/key/encoding"

	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {

	data := []byte("hello world")

	did, err := key.RandomKey("did")

	require.NoError(t, err)

	sig, err := key.Sign("did", did.PriKey(), data)

	require.NoError(t, err)

	pubkey, err := key.Recover("did", sig, data)

	require.NoError(t, err)

	require.Equal(t, pubkey, did.PubKey())

	address := key.PubKeyToAddress("did", pubkey)

	require.NoError(t, err)

	require.Equal(t, address, did.Address())

	ok := key.Verify("did", did.PubKey(), sig, data)

	require.NoError(t, err)

	require.True(t, ok)
}
