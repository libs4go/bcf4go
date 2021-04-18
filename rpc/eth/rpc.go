package rpc

import (
	"encoding/hex"
	"fmt"

	"github.com/dynamicgo/xerrors"
	erc20 "github.com/libs4go/bcf4go/abi/eth"
	"github.com/libs4go/bcf4go/jsonrpc"
	"github.com/libs4go/fixed"
	"github.com/libs4go/slf4go"
)

// Block eth block object
type Block struct {
	Number           string         `json:"number"`
	Hash             string         `json:"hash"`
	Parent           string         `json:"parentHash"`
	Nonce            string         `json:"nonce"`
	SHA3Uncles       string         `json:"sha3Uncles"`
	LogsBloom        string         `json:"logsBloom"`
	TransactionsRoot string         `json:"transactionsRoot"`
	StateRoot        string         `json:"stateRoot"`
	ReceiptsRoot     string         `json:"receiptsRoot"`
	Miner            string         `json:"miner"`
	Difficulty       string         `json:"difficulty"`
	TotalDifficulty  string         `json:"totalDifficulty"`
	ExtraData        string         `json:"extraData"`
	Size             string         `json:"size"`
	GasLimit         string         `json:"gasLimit"`
	GasUsed          string         `json:"gasUsed"`
	Timestamp        string         `json:"timestamp"`
	Transactions     []*Transaction `json:"transactions"`
	Uncles           []string       `json:"uncles"`
}

// Transaction .
type Transaction struct {
	Hash             string `json:"hash"`
	Nonce            string `json:"nonce"`
	BlockHash        string `json:"blockHash"`
	BlockNumber      string `json:"blockNumber"`
	TransactionIndex string `json:"transactionIndex"`
	From             string `json:"from"`
	To               string `json:"to"`
	Value            string `json:"value"`
	GasPrice         string `json:"gasPrice"`
	Gas              string `json:"gas"`
	Input            string `json:"input"`
}

// TransactionReceipt .
type TransactionReceipt struct {
	Hash              string        `json:"transactionHash"`
	BlockHash         string        `json:"blockHash"`
	BlockNumber       string        `json:"blockNumber"`
	TransactionIndex  string        `json:"transactionIndex"`
	CumulativeGasUsed string        `json:"cumulativeGasUsed"`
	GasUsed           string        `json:"gasUsed"`
	ContractAddress   string        `json:"contractAddress"`
	Logs              []interface{} `json:"logs"`
	LogsBloom         string        `json:"logsBloom"`
	Status            string        `json:"status"`
}

// CallSite .
type CallSite struct {
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Value    string `json:"value,omitempty"`
	GasPrice string `json:"gasPrice,omitempty"`
	Gas      string `json:"gas,omitempty"`
	Data     string `json:"data,omitempty"`
}

// Client eth web3 api client
type Client interface {
	Nonce(address string) (uint64, error)
	GetBalance(address string) (*fixed.Number, error)
	BestBlockNumber() (int64, error)
	Call(callsite *CallSite) (val string, err error)
	GetBlockByNumber(number int64) (val *Block, err error)
	GetTransactionByHash(tx string) (val *Transaction, err error)
	SendRawTransaction(tx []byte) (val string, err error)
	GetTransactionReceipt(tx string) (val *TransactionReceipt, err error)
	BalanceOfAsset(address string, asset string, decimals int) (*fixed.Number, error)
	DecimalsOfAsset(asset string) (int, error)
	SuggestGasPrice() (*fixed.Number, error)
}

type clientImpl struct {
	*jsonrpc.RPCClient
	slf4go.Logger
}

// New create new eth web3 client
func New(url string) Client {
	return &clientImpl{
		RPCClient: jsonrpc.NewRPCClient(url),
		Logger:    slf4go.Get("eth-rpc-client"),
	}
}

func (client *clientImpl) GetBalance(address string) (*fixed.Number, error) {

	var data string

	err := client.Call2("eth_getBalance", &data, address, "latest")

	if err != nil {
		return nil, err
	}

	return fixed.New(18, fixed.HexRawValue(data))
}

// BlockNumber get geth last block number
func (client *clientImpl) BestBlockNumber() (int64, error) {

	var data string

	err := client.Call2("eth_blockNumber", &data)

	if err != nil {
		return 0, err
	}

	val, err := fixed.New(0, fixed.HexRawValue(data))

	if err != nil {
		return 0, xerrors.Wrapf(err, "decode %s error", data)
	}

	return val.RawValue.Int64(), nil
}

// Nonce get address send transactions
func (client *clientImpl) Nonce(address string) (uint64, error) {
	var data string

	err := client.Call2("eth_getTransactionCount", &data, address, "latest")

	if err != nil {
		return 0, err
	}

	val, err := fixed.New(0, fixed.HexRawValue(data))

	if err != nil {
		return 0, xerrors.Wrapf(err, "decode %s error", data)
	}

	return uint64(val.RawValue.Int64()), nil
}

func (client *clientImpl) Call(callsite *CallSite) (val string, err error) {

	err = client.Call2("eth_call", &val, callsite, "latest")

	return
}

// BlockByNumber get block by number
func (client *clientImpl) GetBlockByNumber(number int64) (val *Block, err error) {

	err = client.Call2("eth_getBlockByNumber", &val, fmt.Sprintf("0x%x", number), true)

	return
}

// GetTransactionByHash get geth last block number
func (client *clientImpl) GetTransactionByHash(tx string) (val *Transaction, err error) {

	err = client.Call2("eth_getTransactionByHash", &val, tx)

	return
}

// SendRawTransaction .
func (client *clientImpl) SendRawTransaction(tx []byte) (val string, err error) {

	err = client.Call2("eth_sendRawTransaction", &val, "0x"+hex.EncodeToString(tx))

	return
}

// GetTransactionReceipt ...
func (client *clientImpl) GetTransactionReceipt(tx string) (val *TransactionReceipt, err error) {

	err = client.Call2("eth_getTransactionReceipt", &val, tx)

	return
}

// BalanceOfAsset .
func (client *clientImpl) BalanceOfAsset(address string, asset string, decimals int) (*fixed.Number, error) {
	data := erc20.BalanceOf(address)

	valstr, err := client.Call(&CallSite{
		To:   asset,
		Data: data,
	})

	if err != nil {
		return nil, err
	}

	return fixed.New(decimals, fixed.HexRawValue(valstr))
}

// GetTokenDecimals .
func (client *clientImpl) DecimalsOfAsset(asset string) (int, error) {
	data := erc20.GetDecimals()

	valstr, err := client.Call(&CallSite{
		To:   asset,
		Data: data,
	})

	if err != nil {
		return 0, err
	}

	val, err := fixed.New(0, fixed.HexRawValue(valstr))

	if err != nil {
		return 0, xerrors.Wrapf(err, "decode hex %s error", valstr)
	}

	return int(val.RawValue.Int64()), nil
}

// SuggestGasPrice .
func (client *clientImpl) SuggestGasPrice() (*fixed.Number, error) {
	var val string

	err := client.Call2("eth_gasPrice", &val)
	if err != nil {
		return nil, err
	}

	return fixed.New(18, fixed.HexRawValue(val))
}
