// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package hash

import (
	"encoding/hex"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/iotexproject/go-pkgs/util"
)

var (
	// ZeroHash256 is 256-bit of all zero
	ZeroHash256 = Hash256{}
	// ZeroHash160 is 160-bit of all zero
	ZeroHash160 = Hash160{}

	bufPool sync.Pool
)

type (
	// Hash256 is 256-bit hash
	Hash256 [32]byte
	// Hash160 for 160-bit hash used for account and smart contract address
	Hash160 [20]byte
)

func init() {
	bufPool = sync.Pool{
		New: func() interface{} {
			return crypto.NewKeccakState()
		},
	}
}

// Hash160b returns 160-bit (20-byte) hash of input
func Hash160b(input []byte) Hash160 {
	// use sha3 algorithm
	sha3Buf := bufPool.Get().(crypto.KeccakState)
	digest := crypto.HashData(sha3Buf, input)
	bufPool.Put(sha3Buf)
	var hash Hash160
	copy(hash[:], digest[12:])
	return hash
}

// Hash256b returns 256-bit (32-byte) hash of input
func Hash256b(input []byte) Hash256 {
	// use sha3 algorithm
	sha3Buf := bufPool.Get().(crypto.KeccakState)
	sha3Buf.Reset()
	sha3Buf.Write(input)
	var ret Hash256
	sha3Buf.Read(ret[:])
	bufPool.Put(sha3Buf)
	return ret
}

// BytesToHash256 copies the byte slice into hash
func BytesToHash256(b []byte) Hash256 {
	var h Hash256
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(h[32-len(b):], b)
	return h
}

// BytesToHash160 copies the byte slice into hash
func BytesToHash160(b []byte) Hash160 {
	var h Hash160
	if len(b) > 20 {
		b = b[len(b)-20:]
	}
	copy(h[20-len(b):], b)
	return h
}

// HexStringToHash256 decodes the hex string, then copy byte slice into hash
func HexStringToHash256(s string) (Hash256, error) {
	b, err := hex.DecodeString(util.Remove0xPrefix(s))
	if err != nil {
		return ZeroHash256, err
	}
	return BytesToHash256(b), nil
}

// HexStringToHash160 decodes the hex string, then copy byte slice into hash
func HexStringToHash160(s string) (Hash160, error) {
	b, err := hex.DecodeString(util.Remove0xPrefix(s))
	if err != nil {
		return ZeroHash160, err
	}
	return BytesToHash160(b), nil
}
