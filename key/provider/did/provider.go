package eth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/libs4go/bcf4go/base58"
	"github.com/libs4go/bcf4go/ecdsax"
	"github.com/libs4go/bcf4go/ecies"
	"github.com/libs4go/bcf4go/hash160"
	"github.com/libs4go/bcf4go/key"
	"github.com/libs4go/bcf4go/secp256k1"
	"github.com/libs4go/bcf4go/sign"
	"github.com/libs4go/bcf4go/sign/recoverable"
	"github.com/pkg/errors"
)

var version = byte(18)

type didKey struct {
	provider *didProvider
	key      *ecdsa.PrivateKey
	address  string // address
}

func (key *didKey) Address() string {
	return key.address
}

func (key *didKey) Provider() key.Provider {
	return key.provider
}

func (key *didKey) PriKey() []byte {
	return ecdsax.PrivateKeyBytes(key.key)
}

func (key *didKey) PubKey() []byte {
	return ecdsax.PublicKeyBytes(&key.key.PublicKey)
}

type didProvider struct {
	name   string
	vendor string
}

func (provider *didProvider) Name() string {
	return provider.name
}

func (provider *didProvider) RandomKey() (key.Key, error) {
	privateKey, err := ecdsa.GenerateKey(secp256k1.SECP256K1(), rand.Reader)

	if err != nil {
		return nil, errors.Wrap(err, "ecdsa GenerateKey(SECP256K1) error")
	}

	return &didKey{
		provider: provider,
		key:      privateKey,
		address:  provider.PublicKeyToAddress(ecdsax.PublicKeyBytes(&privateKey.PublicKey)),
	}, nil
}

func (provider *didProvider) PublicKeyToAddress(pubkey []byte) string {
	pubBytes := pubkey

	var nonce []byte

	if len(pubBytes) < 32 {
		nonce = make([]byte, 32)
		copy(nonce[:], pubBytes)
	} else {
		nonce = pubBytes[:32]
	}

	hashed := hash160.Hash160(nonce)

	hasher := sha256.New()

	hasher.Write(hashed)

	sum := hasher.Sum(nil)

	hasher.Reset()

	hasher.Write(sum)

	sum = hasher.Sum(nil)

	sum = sum[:3]

	did := append(hashed, sum...)

	return fmt.Sprintf("did:%s:%s", provider.vendor, base58.CheckEncode(did, version))
}

func (provider *didProvider) FromPriKey(priKey []byte) (key.Key, error) {
	privateKey := ecdsax.BytesToPrivateKey(priKey, secp256k1.SECP256K1())

	return &didKey{
		provider: provider,
		key:      privateKey,
		address:  provider.PublicKeyToAddress(ecdsax.PublicKeyBytes(&privateKey.PublicKey)),
	}, nil
}

func (provider *didProvider) Verify(pubkey []byte, sig []byte, hash []byte) bool {

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

	publicKey, _, err := recoverable.Recover(curve, signature, hash)

	if err != nil {
		return false
	}

	return signature.Verfiy(publicKey, hash)
}

func (provider *didProvider) Recover(sig []byte, hash []byte) (pubkey []byte, err error) {
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

func (provider *didProvider) ValidAddress(address string) bool {

	tokens := strings.Split(address, ":")

	if len(tokens) != 3 {
		return false
	}

	if tokens[0] != provider.vendor {
		return false
	}

	_, v, err := base58.CheckDecode(tokens[2])

	if err != nil {
		return false
	}

	return v == version
}

func (provider *didProvider) PrivateToPublic(privateKey []byte) []byte {
	key := ecdsax.BytesToPrivateKey(privateKey, secp256k1.SECP256K1())

	return ecdsax.PublicKeyBytes(&key.PublicKey)
}

func (provider *didProvider) Curve() elliptic.Curve {
	return secp256k1.SECP256K1()
}

// EncryptBlock .
func (provider *didProvider) Encrypt(pubkey []byte, message []byte) ([]byte, error) {

	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(ecdsax.BytesToPublicKey(provider.Curve(), pubkey)), message, nil, nil)
}

// DecryptBlock .
func (provider *didProvider) Decrypt(privkey []byte, message []byte) ([]byte, error) {
	return ecies.ImportECDSA(ecdsax.BytesToPrivateKey(privkey, provider.Curve())).Decrypt(message, nil, nil)
}

func (provider *didProvider) Sign(priKey []byte, hashed []byte) ([]byte, error) {

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

func init() {
	key.RegisterProvider(&didProvider{name: "did", vendor: "lib4go"})
}

// Vendor register vendor did provider
func Vendor(name string) {
	key.RegisterProvider(&didProvider{name: "did", vendor: name})
}
