package eth

import (
	"fmt"
	"testing"

	"github.com/libs4go/fixed"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	encodeTest("balanceOf(address)")
	// encodeTest("nonces")
	// encodeTest("decimals")
	// encodeTest("allowance")

	n, err := fixed.New(18, fixed.Float(3229.9))

	require.NoError(t, err)

	require.Equal(t, "0000000000000000000000000000000000000000000000af17dde941a22e0000", PackNumeric(n.HexRawValue(), 32))

}

func encodeTest(method string) {
	println(fmt.Sprintf("%s: %s", method, Encode(method)))
}
