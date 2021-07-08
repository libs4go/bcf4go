package eth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/libs4go/bcf4go/ecdsax"
	"github.com/libs4go/bcf4go/ecies"
	"github.com/libs4go/bcf4go/key"
	"github.com/libs4go/bcf4go/secp256k1"
	"github.com/libs4go/bcf4go/sha3"
	"github.com/libs4go/bcf4go/sign"
	"github.com/libs4go/bcf4go/sign/recoverable"
	"github.com/pkg/errors"
)

type ethKey struct {
	provider *ethProvider
	key      *ecdsa.PrivateKey
	address  string // address
}

func (key *ethKey) Address() string {
	return key.address
}

func (key *ethKey) Provider() key.Provider {
	return key.provider
}

func (key *ethKey) PriKey() []byte {
	return ecdsax.PrivateKeyBytes(key.key)
}

func (key *ethKey) PubKey() []byte {
	return ecdsax.PublicKeyBytes(&key.key.PublicKey)
}

type ethProvider struct {
	name string
}

func (provider *ethProvider) Name() string {
	return provider.name
}

func (provider *ethProvider) RandomKey() (key.Key, error) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	if err != nil {
		return nil, errors.Wrap(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &ethKey{
		provider: provider,
		key:      privateKey,
		address:  provider.PublicKeyToAddress(ecdsax.PublicKeyBytes(&privateKey.PublicKey)),
	}, nil
}

func (provider *ethProvider) PublicKeyToAddress(pubkey []byte) string {
	pubBytes := pubkey

	hasher := sha3.NewKeccak256()

	hasher.Write(pubBytes[1:])

	pubBytes = hasher.Sum(nil)[12:]

	if len(pubBytes) > 20 {
		pubBytes = pubBytes[len(pubBytes)-20:]
	}

	address := make([]byte, 20)

	copy(address[20-len(pubBytes):], pubBytes)

	unchecksummed := hex.EncodeToString(address)

	sha := sha3.NewKeccak256()

	sha.Write([]byte(unchecksummed))

	hash := sha.Sum(nil)

	result := []byte(unchecksummed)

	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}

	return "0x" + string(result)
}

func (provider *ethProvider) FromPriKey(priKey []byte) (key.Key, error) {
	privateKey := ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())

	return &ethKey{
		provider: provider,
		key:      privateKey,
		address:  provider.PublicKeyToAddress(ecdsax.PublicKeyBytes(&privateKey.PublicKey)),
	}, nil
}

func (provider *ethProvider) Verify(pubkey []byte, sig []byte, hash []byte) bool {

	curve := secp256k1.SECP256K1()

	size := curve.Params().BitSize / 8

	if len(sig) != 2*size+1 {
		return false
	}

	signature := &sign.Signature{
		R: new(big.Int).SetBytes(sig[:size]),
		S: new(big.Int).SetBytes(sig[size : 2*size]),
		V: new(big.Int).SetBytes(sig[2*size:]),
	}

	// publicKey, _, err := recoverable.Recover(curve, signature, hash)

	// if err != nil {
	// 	return false
	// }

	return signature.Verfiy(ecdsax.BytesToPublicKey(curve, pubkey), hash)
}

func (provider *ethProvider) Recover(sig []byte, hash []byte) (pubkey []byte, err error) {
	curve := secp256k1.SECP256K1()

	size := curve.Params().BitSize / 8

	if len(sig) != 2*size+1 {
		return nil, errors.Errorf("public key length error")
	}

	signature := &sign.Signature{
		R: new(big.Int).SetBytes(sig[:size]),
		S: new(big.Int).SetBytes(sig[size : 2*size]),
		V: new(big.Int).SetBytes(sig[2*size:]),
	}

	publicKey, _, err := recoverable.Recover(curve, signature, hash)

	return ecdsax.PublicKeyBytes(publicKey), nil
}

func (provider *ethProvider) ValidAddress(address string) bool {

	address = strings.TrimPrefix(address, "0x")

	if len(address) != 40 {
		return false
	}

	_, err := hex.DecodeString(address)

	if err != nil {
		return false
	}

	return true
}

func (provider *ethProvider) Curve() elliptic.Curve {
	return secp256k1.SECP256K1()
}

func (provider *ethProvider) Sign(priKey []byte, hashed []byte) ([]byte, error) {

	privateKey := ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())

	sig, err := recoverable.Sign(privateKey, hashed, false)

	if err != nil {
		return nil, err
	}

	size := privateKey.Curve.Params().BitSize / 8

	buff := make([]byte, 2*size+1)

	r := sig.R.Bytes()

	if len(r) > size {
		r = r[:size]
	}

	s := sig.S.Bytes()

	if len(s) > size {
		s = s[:size]
	}

	copy(buff[size-len(r):size], r)
	copy(buff[2*size-len(s):2*size], s)
	buff[2*size] = sig.V.Bytes()[0]

	return buff, nil
}

func (provider *ethProvider) PrivateToPublic(privateKey []byte) []byte {
	key := ecdsax.BytesToPrivateKey(privateKey, secp256k1.SECP256K1())

	return ecdsax.PublicKeyBytes(&key.PublicKey)
}

// EncryptBlock .
func (provider *ethProvider) Encrypt(pubkey []byte, message []byte) ([]byte, error) {

	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(ecdsax.BytesToPublicKey(provider.Curve(), pubkey)), message, nil, nil)
}

// DecryptBlock .
func (provider *ethProvider) Decrypt(privkey []byte, message []byte) ([]byte, error) {
	return ecies.ImportECDSA(ecdsax.BytesToPrivateKey(privkey, provider.Curve())).Decrypt(message, nil, nil)
}

func init() {
	key.RegisterProvider(&ethProvider{name: "eth"})
}
