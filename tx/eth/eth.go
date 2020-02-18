package eth

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/libs4go/bcf4go/rlp"
	"github.com/libs4go/bcf4go/sha3"
	"github.com/libs4go/fixed"
)

// Tx .
type Tx struct {
	AccountNonce uint64    `json:"nonce"    gencodec:"required"`
	Price        *big.Int  `json:"gasPrice" gencodec:"required"`
	GasLimit     *big.Int  `json:"gas"      gencodec:"required"`
	Recipient    *[20]byte `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int  `json:"value"    gencodec:"required"`
	Payload      []byte    `json:"input"    gencodec:"required"`
	V            *big.Int  `json:"v" gencodec:"required"`
	R            *big.Int  `json:"r" gencodec:"required"`
	S            *big.Int  `json:"s" gencodec:"required"`
}

// New create new eth tx
func New(nonce uint64, to string, amount, gasPrice *fixed.Number, gasLimit *big.Int, data []byte) *Tx {

	var recpoint *[20]byte

	if to != "" {
		var recipient [20]byte

		to = strings.TrimPrefix(to, "0x")

		toBytes, _ := hex.DecodeString(to)

		copy(recipient[:], toBytes)

		recpoint = &recipient
	}

	tx := &Tx{
		AccountNonce: nonce,
		Recipient:    recpoint,
		Payload:      data,
		GasLimit:     gasLimit,
		Price:        new(big.Int).Set(gasPrice.RawValue),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}

	if amount != nil {
		tx.Amount = new(big.Int).Set(amount.RawValue)
	}

	return tx
}

// Sign .
func (tx *Tx) Sign(signF func([]byte) ([]byte, error)) (string, error) {
	hw := sha3.NewKeccak256()

	rlp.Encode(hw, []interface{}{
		tx.AccountNonce,
		tx.Price,
		tx.GasLimit,
		tx.Recipient,
		tx.Amount,
		tx.Payload,
	})

	var hash [32]byte

	hw.Sum(hash[:0])

	sig, err := signF(hash[:])

	if err != nil {
		return "", err
	}

	tx.R = new(big.Int).SetBytes(sig[:32])
	tx.S = new(big.Int).SetBytes(sig[32:64])
	tx.V = new(big.Int).SetBytes(sig[64:])

	return tx.Hash(), nil
}

// Hash get tx hash string
func (tx *Tx) Hash() string {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, tx)
	return "0x" + hex.EncodeToString(hw.Sum(nil))
}

// Encode .
func (tx *Tx) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(tx)
}
