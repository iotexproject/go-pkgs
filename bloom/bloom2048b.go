// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package bloom

import (
	"github.com/iotexproject/go-pkgs/hash"
	"github.com/pkg/errors"
)

type (
	// bloom2048b implements a 2048-bit bloom filter
	bloom2048b struct {
		array   [256]byte
		numHash int // number of hash function
	}
)

// Add 32-byte key into bloom filter
func (f *bloom2048b) Add(key hash.Hash256) {
	h := hash.Hash256b(key[:])
	// each 2-byte pair used as output of hash function
	for i := 0; i < f.numHash; i++ {
		f.setBit(h[2*i], h[2*i+1])
	}
}

// Exist checks if a key is in bloom filter
func (f *bloom2048b) Exist(key hash.Hash256) bool {
	h := hash.Hash256b(key[:])
	for i := 0; i < f.numHash; i++ {
		if !f.chkBit(h[2*i], h[2*i+1]) {
			return false
		}
	}
	return true
}

// Bytes returns the bytes of bloom filter
func (f *bloom2048b) Bytes() []byte {
	return f.array[:]
}

// SetBytes copies the bytes into bloom filter
func (f *bloom2048b) SetBytes(b []byte) error {
	if len(b) != 256 {
		return errors.Errorf("wrong length %d, expecting 256", len(b))
	}
	copy(f.array[:], b[:])
	return nil
}

func (f *bloom2048b) setBit(bytePos, bitPos byte) {
	// bytePos indicates which byte to set
	// lower 3-bit of bitPos indicates which bit to set
	mask := 1 << (bitPos & 7)
	f.array[bytePos] |= byte(mask)
}

func (f *bloom2048b) chkBit(bytePos, bitPos byte) bool {
	mask := 1 << (bitPos & 7)
	return (f.array[bytePos] & byte(mask)) != 0
}
