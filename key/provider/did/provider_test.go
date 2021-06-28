package did

import (
	"encoding/hex"
	"testing"

	"github.com/libs4go/bcf4go/key"
	_ "github.com/libs4go/bcf4go/key/encoding"
	_ "github.com/libs4go/bcf4go/key/provider/eth"

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

func TestEncryptBlock(t *testing.T) {
	k, err := key.RandomKey("did")
	require.NoError(t, err)

	c, err := key.Encrypt("did", k.PubKey(), []byte("hello world"))

	require.NoError(t, err)

	println(hex.EncodeToString(c))

	c, err = key.Decrypt("did", k.PriKey(), c)

	require.NoError(t, err)

	require.Equal(t, c, []byte("hello world"))
}

func TestMnemonic(t *testing.T) {
	mnemonic, err := key.RandomMnemonic(32)

	require.NoError(t, err)

	k, err := key.DriveKey("did", mnemonic, "m/44'/201910'/0'/0/0")

	require.NoError(t, err)

	println(k.Address())
}
