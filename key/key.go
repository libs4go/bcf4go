package key

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"

	"github.com/libs4go/bcf4go/bip32"

	"github.com/libs4go/bcf4go/bip39"
	"github.com/libs4go/errors"
)

// Property .
type Property map[string]string

// Key blockchain signature alogirthm facade
type Key interface {
	Address() string    // address display string
	PriKey() []byte     // private key byte array
	PubKey() []byte     // public key byte array
	Provider() Provider // provider
}

// Provider blockchain signature alogrithm provider
type Provider interface {
	Name() string                                       // provider unique name
	RandomKey() (Key, error)                            // create new random key
	FromPriKey(priKey []byte) (Key, error)              // create key facade with private key bytes
	Verify(pubkey []byte, sig []byte, hash []byte) bool // verify signature
	Sign(prikey []byte, hashed []byte) ([]byte, error)  // sign the hashed message
}

// EllipticProvider .
type EllipticProvider interface {
	Curve() elliptic.Curve
}

// AddressProvider .
type AddressProvider interface {
	PublicKeyToAddress(pubkey []byte) string
	PrivateToPublic(privateKey []byte) []byte
	ValidAddress(address string) bool
}

// RecoverableProvider .
type RecoverableProvider interface {
	Recover(sig []byte, hash []byte) (pubkey []byte, err error)
}

// EncryptProvider .
type EncryptProvider interface {
	Encrypt(pubkey []byte, block []byte) ([]byte, error)
	Decrypt(privkey []byte, block []byte) ([]byte, error)
}

// Encoding the key format encoding facade
type Encoding interface {
	Name() string
	Encode(privKey []byte, property Property, writer io.Writer) error
	Decode(property Property, reader io.Reader) ([]byte, error)
}

// Sign .
func Sign(providerName string, prikey []byte, hashed []byte) ([]byte, error) {
	var provider Provider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.Sign(prikey, hashed)
}

// Verify .
func Verify(providerName string, pubkey []byte, sig []byte, hash []byte) bool {
	var provider Provider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.Verify(pubkey, sig, hash)
}

// Curve .
func Curve(key Key) elliptic.Curve {
	providerName := key.Provider().Name()

	var provider EllipticProvider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.Curve()
}

// PubKeyToAddress .
func PubKeyToAddress(providerName string, pubkey []byte) string {
	var provider AddressProvider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.PublicKeyToAddress(pubkey)
}

// PriKeyToPubKey .
func PriKeyToPubKey(providerName string, prikey []byte) []byte {
	var provider AddressProvider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.PrivateToPublic(prikey)
}

// ValidAddress .
func ValidAddress(providerName string, address string) bool {
	var provider AddressProvider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.ValidAddress(address)
}

// Recover .
func Recover(providerName string, sig []byte, hash []byte) ([]byte, error) {

	var provider RecoverableProvider

	if err := getProvider(providerName, &provider); err != nil {
		return nil, errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName)
	}

	return provider.Recover(sig, hash)
}

// RandomKey create random key with provider name
func RandomKey(providerName string) (Key, error) {

	var provider Provider

	if err := getProvider(providerName, &provider); err != nil {
		return nil, errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName)
	}

	return provider.RandomKey()
}

// FromPriKey create key with provider name
func FromPriKey(providerName string, privKey []byte) (Key, error) {
	var provider Provider

	if err := getProvider(providerName, &provider); err != nil {
		return nil, errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName)
	}

	return provider.FromPriKey(privKey)
}

// As convert key to another type key with provider name
func As(key Key, providerName string) (Key, error) {
	return FromPriKey(providerName, key.PriKey())
}

// Encode encode key with encoding name
func Encode(encodingName string, privKey []byte, property Property, writer io.Writer) error {

	var encoding Encoding

	if err := getEncoding(encodingName, &encoding); err != nil {
		panic(errors.Wrap(err, "encoding %s not found, call RegisterEncoding first", encodingName))
	}

	return encoding.Encode(privKey, property, writer)
}

// Decode decode key with encoding name
func Decode(encodingName string, property Property, reader io.Reader) ([]byte, error) {

	var encoding Encoding

	if err := getEncoding(encodingName, &encoding); err != nil {
		panic(errors.Wrap(err, "encoding %s not found, call RegisterEncoding first", encodingName))
	}

	privKey, err := encoding.Decode(property, reader)

	if err != nil {
		return nil, errors.Wrap(err, "decode key error")
	}

	return privKey, nil
}

// Encrypt .
func Encrypt(providerName string, pubkey []byte, block []byte) ([]byte, error) {
	var provider EncryptProvider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.Encrypt(pubkey, block)
}

// Decrypt .
func Decrypt(providerName string, privkey []byte, block []byte) ([]byte, error) {
	var provider EncryptProvider

	if err := getProvider(providerName, &provider); err != nil {
		panic(errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName))
	}

	return provider.Decrypt(privkey, block)
}

// RandomMnemonic generate random mnemonic with provide length
func RandomMnemonic(length int) (string, error) {
	seed := make([]byte, length)

	_, err := rand.Read(seed)

	if err != nil {
		return "", errors.Wrap(err, "create seed error")
	}

	mnemonic, err := bip39.NewMnemonic(seed, bip39.ENUS())

	if err != nil {
		return "", errors.Wrap(err, "create mnemonic error")
	}

	return mnemonic, nil
}

// DriveKey drive key use bip32
func DriveKey(providerName string, mnemonic string, path string) (Key, error) {
	var provider EllipticProvider

	if err := getProvider(providerName, &provider); err != nil {
		errors.Wrap(err, "provider with name %s not found, call RegisterProvider first", providerName)
	}

	masterkey, err := bip32.FromMnemonic(provider, mnemonic, "")

	if err != nil {
		return nil, errors.Wrap(err, "create master key from mnemonic error")
	}

	privateKeyBytes, err := bip32.DriveFrom(masterkey, path)

	if err != nil {
		return nil, err
	}

	return FromPriKey(providerName, privateKeyBytes)
}
