package recoverable

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/libs4go/bcf4go/secp256k1"
	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	sign, err := Sign(privateKey, []byte(source), false)

	require.NoError(t, err)

	require.True(t, sign.Verfiy(&privateKey.PublicKey, []byte(source)))

	publicKey, compressed, err := Recover(privateKey.Curve, sign, []byte(source))

	require.NoError(t, err)

	require.False(t, compressed)

	require.Equal(t, publicKey.X, privateKey.PublicKey.X)
	require.Equal(t, publicKey.Y, privateKey.PublicKey.Y)
}
func TestK(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	sign, err := Sign(privateKey, []byte("hello rfc6979"), false)

	require.NoError(t, err)

	sign1, err := Sign(privateKey, []byte("hello rfc6971119"), false)

	require.NoError(t, err)

	require.NotEqual(t, sign.R, sign1.R)
}

func TestCompressSignVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	sign, err := Sign(privateKey, []byte(source), true)

	require.NoError(t, err)

	require.True(t, sign.Verfiy(&privateKey.PublicKey, []byte(source)))

	publicKey, compressed, err := Recover(privateKey.Curve, sign, []byte(source))

	require.NoError(t, err)

	require.True(t, compressed)

	require.Equal(t, publicKey.X, privateKey.PublicKey.X)
	require.Equal(t, publicKey.Y, privateKey.PublicKey.Y)
}
