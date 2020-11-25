// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/dustinxie/gmsm/sm2"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/iotexproject/iotex-address/address"
	"github.com/pkg/errors"

	"github.com/iotexproject/go-pkgs/hash"
)

type (
	// P256sm2PrvKey implements the P256sm2 private key
	P256sm2PrvKey struct {
		*sm2.PrivateKey
	}
	// P256sm2PubKey implements the P256sm2 public key
	P256sm2PubKey struct {
		*sm2.PublicKey
	}
)

// WritePrivateKeyToPem writes the private key to PEM file
func WritePrivateKeyToPem(file string, key *P256sm2PrvKey, pwd string) error {
	_, err := sm2.WritePrivateKeytoPem(file, key.PrivateKey, []byte(pwd))
	return err
}

// WritePublicKeyToPem writes the public key to PEM file
func WritePublicKeyToPem(file string, key *P256sm2PubKey, pwd string) error {
	_, err := sm2.WritePublicKeytoPem(file, key.PublicKey, []byte(pwd))
	return err
}

// ReadPrivateKeyFromPem reads the private key from PEM file
func ReadPrivateKeyFromPem(file string, pwd string) (PrivateKey, error) {
	sk, err := sm2.ReadPrivateKeyFromPem(file, []byte(pwd))
	if err != nil {
		return nil, err
	}
	return &P256sm2PrvKey{
		PrivateKey: sk,
	}, nil
}

// ReadPublicKeyFromPem reads the public key from PEM file
func ReadPublicKeyFromPem(file string, pwd string) (PublicKey, error) {
	pk, err := sm2.ReadPublicKeyFromPem(file, []byte(pwd))
	if err != nil {
		return nil, err
	}
	return &P256sm2PubKey{
		PublicKey: pk,
	}, nil
}

// UpdatePrivateKeyPasswordToPem updates private key's password for PEM file
func UpdatePrivateKeyPasswordToPem(fileName string, oldPwd string, newPwd string) error {
	key, err := sm2.ReadPrivateKeyFromPem(fileName, []byte(oldPwd))
	if err != nil {
		return err
	}

	var block *pem.Block

	der, err := sm2.MarshalSm2PrivateKey(key, []byte(newPwd))
	if err != nil {
		return err
	}
	if newPwd != "" {
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: der,
		}
	} else {
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
	file, err := os.OpenFile(fileName, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, block)
}

//======================================
// PrivateKey function
//======================================

// newP256sm2PrvKey generates a new P256sm2 private key
func newP256sm2PrvKey() (PrivateKey, error) {
	sk, err := sm2.GenerateKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create p256sm2 private key")
	}
	return &P256sm2PrvKey{
		PrivateKey: sk,
	}, nil
}

// newP256sm2PrvKeyFromBytes converts bytes format to PrivateKey
func newP256sm2PrvKeyFromBytes(b []byte) (PrivateKey, error) {
	sk, err := sm2.ParsePKCS8UnecryptedPrivateKey(b)
	if err != nil {
		return nil, errors.Wrap(ErrPrivateKey, err.Error())
	}
	return &P256sm2PrvKey{
		PrivateKey: sk,
	}, nil
}

// Bytes returns the private key in bytes representation
func (k *P256sm2PrvKey) Bytes() []byte {
	b, _ := sm2.MarshalSm2UnecryptedPrivateKey(k.PrivateKey)
	return b
}

// HexString returns the private key in hex string
func (k *P256sm2PrvKey) HexString() string {
	return hex.EncodeToString(k.Bytes())
}

// EcdsaPrivateKey returns the embedded ecdsa private key
func (k *P256sm2PrvKey) EcdsaPrivateKey() interface{} {
	return k
}

// PublicKey returns the public key corresponding to private key
func (k *P256sm2PrvKey) PublicKey() PublicKey {
	return &P256sm2PubKey{
		PublicKey: &k.PrivateKey.PublicKey,
	}
}

// Sign signs the message/hash
func (k *P256sm2PrvKey) Sign(hash []byte) ([]byte, error) {
	return k.PrivateKey.Sign(rand.Reader, hash, nil)
}

// Zero zeroes the private key data
func (k *P256sm2PrvKey) Zero() {
	b := k.PrivateKey.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

// D returns the secret D in big-endian
func (k *P256sm2PrvKey) D() []byte {
	if k.PrivateKey == nil || k.PrivateKey.D == nil {
		return nil
	}
	return math.PaddedBigBytes(k.PrivateKey.D, k.PrivateKey.Curve.Params().BitSize/8)
}

// newP256sm2PrvKeyFromD converts secret D to PrivateKey
func newP256sm2PrvKeyFromD(d []byte) (PrivateKey, error) {
	sk := new(sm2.PrivateKey)
	sk.PublicKey.Curve = sm2.P256Sm2()
	if 8*len(d) != sk.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", sk.Params().BitSize)
	}
	sk.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if sk.D.Cmp(sk.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if sk.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	sk.PublicKey.X, sk.PublicKey.Y = sk.PublicKey.Curve.ScalarBaseMult(d)
	if sk.PublicKey.X == nil {
		return nil, ErrPrivateKey
	}
	return &P256sm2PrvKey{
		PrivateKey: sk,
	}, nil
}

//======================================
// PublicKey function
//======================================

// newP256sm2PubKeyFromBytes converts bytes format to PublicKey
func newP256sm2PubKeyFromBytes(b []byte) (PublicKey, error) {
	pk, err := sm2.ParseSm2PublicKey(b)
	if err != nil {
		return nil, err
	}
	return &P256sm2PubKey{
		PublicKey: pk,
	}, nil
}

// Bytes returns the public key in bytes representation
func (k *P256sm2PubKey) Bytes() []byte {
	b, _ := sm2.MarshalSm2PublicKey(k.PublicKey)
	return b
}

// HexString returns the public key in hex string
func (k *P256sm2PubKey) HexString() string {
	return hex.EncodeToString(k.Bytes())
}

// EcdsaPublicKey returns the embedded ecdsa publick key
func (k *P256sm2PubKey) EcdsaPublicKey() interface{} {
	return k
}

// Hash is the last 20-byte of keccak hash of public key (X, Y) co-ordinate
func (k *P256sm2PubKey) Hash() []byte {
	if k.PublicKey == nil || k.PublicKey.X == nil || k.PublicKey.Y == nil {
		return nil
	}
	h := hash.Hash160b(elliptic.Marshal(sm2.P256Sm2(), k.PublicKey.X, k.PublicKey.Y)[1:])
	return h[:]
}

// Verify verifies the signature
func (k *P256sm2PubKey) Verify(hash, sig []byte) bool {
	return k.PublicKey.Verify(hash, sig)
}

// Address returns the address object
func (k *P256sm2PubKey) Address() address.Address {
	addr, _ := address.FromBytes(k.Hash())
	return addr
}
