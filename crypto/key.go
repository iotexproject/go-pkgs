// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"encoding/hex"
	"io/ioutil"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/iotexproject/iotex-address/address"
	"github.com/pkg/errors"
)

// const
const (
	// 64-byte (r, s) format
	Secp256k1SigSize = 64

	// 65-byte (r, s, v) format, where v is the recovery id
	Secp256k1SigSizeWithRecID = 65
)

const (
	secp256pubKeyLength = 65
	secp256prvKeyLength = 32
)

var (
	// ErrInvalidKey is the error that the key format is invalid
	ErrInvalidKey = errors.New("invalid key format")
	// ErrPublicKey indicates the error of public key
	ErrPublicKey = errors.New("invalid public key")
	// ErrPrivateKey indicates the error of private key
	ErrPrivateKey = errors.New("invalid private key")
)

type (
	// PublicKey represents a public key
	PublicKey interface {
		Bytes() []byte
		HexString() string
		EcdsaPublicKey() interface{}
		Hash() []byte
		Verify([]byte, []byte) bool
		Address() address.Address
	}
	// PrivateKey represents a private key
	PrivateKey interface {
		Bytes() []byte
		HexString() string
		EcdsaPrivateKey() interface{}
		PublicKey() PublicKey
		Sign([]byte) ([]byte, error)
		Zero()
	}
)

// GenerateKey generates a SECP256k1 PrivateKey
func GenerateKey() (PrivateKey, error) {
	return newSecp256k1PrvKey()
}

// GenerateKeySm2 generates a P256sm2 PrivateKey
func GenerateKeySm2() (PrivateKey, error) {
	return newP256sm2PrvKey()
}

func has0xPrefix(s string) bool {
	if len(s) > 1 {
		if s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
			return true
		}
	}
	return false
}

// HexStringToPublicKey decodes a string to PublicKey
func HexStringToPublicKey(pubKey string) (PublicKey, error) {
	if has0xPrefix(pubKey) {
		pubKey = pubKey[2:]
	}
	b, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode public key %s", pubKey)
	}
	return BytesToPublicKey(b)
}

// HexStringToPrivateKey decodes a string to PrivateKey
func HexStringToPrivateKey(prvKey string) (PrivateKey, error) {
	if has0xPrefix(prvKey) {
		prvKey = prvKey[2:]
	}
	b, err := hex.DecodeString(prvKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode public key %s", prvKey)
	}
	return BytesToPrivateKey(b)
}

// BytesToPublicKey converts a byte slice to SECP256K1 PublicKey
func BytesToPublicKey(pubKey []byte) (PublicKey, error) {
	if len(pubKey) == secp256pubKeyLength-1 {
		pubKey = append([]byte{4}, pubKey...)
	}

	// check against P256k1
	if len(pubKey) == secp256pubKeyLength {
		return newSecp256k1PubKeyFromBytes(pubKey)
	}

	// check against P256sm2
	if k, err := newP256sm2PubKeyFromBytes(pubKey); err == nil {
		return k, nil
	}
	return nil, ErrPublicKey
}

// BytesToPrivateKey converts a byte slice to SECP256K1 PrivateKey
func BytesToPrivateKey(prvKey []byte) (PrivateKey, error) {
	// check against P256sm2
	if len(prvKey) == secp256prvKeyLength {
		return newSecp256k1PrvKeyFromBytes(prvKey)
	}

	// check against P256sm2
	if k, err := newP256sm2PrvKeyFromBytes(prvKey); err == nil {
		return k, nil
	}
	return nil, ErrPrivateKey
}

// KeystoreToPrivateKey generates PrivateKey from Keystore account
func KeystoreToPrivateKey(account accounts.Account, password string) (PrivateKey, error) {
	// load the key from the keystore
	keyJSON, err := ioutil.ReadFile(account.URL.Path)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(keyJSON, password)
	if err != nil {
		return nil, err
	}
	return &secp256k1PrvKey{
		PrivateKey: key.PrivateKey,
	}, nil
}

// RecoverPubkey recovers the public key from signature
func RecoverPubkey(msg, sig []byte) (PublicKey, error) {
	if pk, err := recoverSecp256k1(msg, sig); err == nil {
		return pk, nil
	}
	// TODO: implement recover key for sm2
	return nil, ErrInvalidKey
}

func recoverSecp256k1(msg, sig []byte) (PublicKey, error) {
	if len(sig) >= Secp256k1SigSizeWithRecID && sig[Secp256k1SigSize] >= 27 {
		// when an Ethereum signature is calculated, 27 is added to recovery id
		// https://github.com/ethereum/go-ethereum/commit/b59c8399fbe42390a3d41e945d03b1f21c1a9b8d#diff-31c4aa3a4249d4755fc652d3e0087b98R226-R232
		sig[Secp256k1SigSize] -= 27
		defer func() {
			sig[Secp256k1SigSize] += 27
		}()
	}

	pk, err := secp256k1.RecoverPubkey(msg, sig)
	if err != nil {
		return nil, err
	}
	return newSecp256k1PubKeyFromBytes(pk)
}
