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
		numHash uint // number of hash function
	}
)

// newBloom2048 returns a 2048-bit bloom filter
func newBloom2048(h uint) (BloomFilter, error) {
	if h == 0 || h > 16 {
		return nil, errors.New("expecting 0 < number of hash functions <= 16")
	}
	return &bloom2048b{numHash: h}, nil
}

// bloom2048FromBytes constructs a 2048-bit bloom filter from bytes
func bloom2048FromBytes(b []byte, h uint) (BloomFilter, error) {
	if h == 0 || h > 16 {
		return nil, errors.New("expecting 0 < number of hash functions <= 16")
	}
	if len(b) != 256 {
		return nil, errors.Errorf("wrong length %d, expecting 256", len(b))
	}
	f := bloom2048b{numHash: h}
	copy(f.array[:], b[:])
	return &f, nil
}

// Size of bloom filter in bits
func (b *bloom2048b) Size() uint64 {
	return 2048
}

// NumHash is the number of hash functions used
func (b *bloom2048b) NumHash() uint64 {
	return uint64(b.numHash)
}

// NumElements is the number of elements in the bloom filter
func (b *bloom2048b) NumElements() uint64 {
	// this is new API, does not apply to 2048-bit
	return 0
}

// Add 32-byte key into bloom filter
func (f *bloom2048b) Add(key []byte) {
	if key == nil {
		return
	}
	h := hash.Hash256b(key)
	// each 2-byte pair used as output of hash function
	for i := uint(0); i < f.numHash; i++ {
		f.setBit(h[2*i], h[2*i+1])
	}
}

// Exist checks if a key is in bloom filter
func (f *bloom2048b) Exist(key []byte) bool {
	if key == nil {
		return false
	}
	h := hash.Hash256b(key)
	for i := uint(0); i < f.numHash; i++ {
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
