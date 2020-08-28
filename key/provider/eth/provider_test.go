package eth

import (
	"encoding/hex"
	"testing"

	"github.com/libs4go/bcf4go/key"
	_ "github.com/libs4go/bcf4go/key/encoding"

	"github.com/stretchr/testify/require"
)

func TestEthKey(t *testing.T) {
	k, err := key.RandomKey("eth")
	require.NoError(t, err)

	println("address", k.Address())

	println(len(k.PriKey()))
}

// func TestWeb3Encryptor(t *testing.T) {
// 	k, err := key.RandomKey("eth")

// 	require.NoError(t, err)

// 	var buff bytes.Buffer

// 	err = key.Encode("web3.standard", k.PriKey(), map[string]string{
// 		"password": "test",
// 		"address":  k.Address(),
// 	}, &buff)

// 	require.NoError(t, err)

// 	println(buff.String())

// 	k2, err := key.Decode("web3.standard", "eth", map[string]string{
// 		"password": "test",
// 	}, &buff)

// 	require.NoError(t, err)

// 	require.Equal(t, k.Address(), k2.Address())
// 	require.Equal(t, k.PriKey(), k2.PriKey())

// }

func TestMnemonic(t *testing.T) {
	mnemonic, err := key.RandomMnemonic(16)

	require.NoError(t, err)

	println(mnemonic)

	k, err := key.DriveKey("eth", mnemonic, "m/44'/60'/0'/0/0")

	require.NoError(t, err)

	println(k.Address())
}

func TestFromMnemonic(t *testing.T) {
	k, err := key.DriveKey("eth", "canal walnut regular license dust liberty story expect repeat design picture medal", "m/44'/60'/0'/0/0")

	require.NoError(t, err)

	println(k.Address())

	println(hex.EncodeToString(k.PriKey()))
}
