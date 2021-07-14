package rfc6979

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/libs4go/bcf4go/secp256k1"
)

func TestSignVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	sign, err := Sign(privateKey, []byte(source))

	require.NoError(t, err)

	require.True(t, sign.Verfiy(&privateKey.PublicKey, []byte(source)))
}

func TestK(t *testing.T) {
	k1, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	k2, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	require.NoError(t, err)

	source := "hello rfc6979"

	s1, err := Sign(k1, []byte(source))

	require.NoError(t, err)

	s2, err := Sign(k2, []byte(source))

	require.NoError(t, err)

	require.NotEqual(t, s1.R, s2.R)
}
