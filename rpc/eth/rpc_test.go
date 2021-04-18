package rpc

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var client Client

func init() {
	client = New("https://mainnet.infura.io/v3/44ab06a5fca644df953378ac1c16d2b9")
}

func TestGasPrice(t *testing.T) {
	price, err := client.SuggestGasPrice()

	require.NoError(t, err)

	println(fmt.Sprintf("price %s", price))

	decimals, err := client.DecimalsOfAsset("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2")
	require.NoError(t, err)
	println(fmt.Sprintf("%d", decimals))
}

func TestHex(t *testing.T) {
	b, err := hex.DecodeString("7472616e73666572")
	assert.NoError(t, err)
	println(string(b))
}

func TestBlance(t *testing.T) {
	val, err := client.GetBalance("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2")
	require.NoError(t, err)
	println(val.String())
}
