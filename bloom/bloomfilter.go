// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package bloom

import (
	"github.com/pkg/errors"
)

type (
	// BloomFilter interface
	BloomFilter interface {
		// Size of bloom filter in bits
		Size() uint64

		// NumHash is the number of hash functions used
		NumHash() uint64

		// NumElements is the number of elements in the bloom filter
		NumElements() uint64

		// Add key into bloom filter
		Add([]byte)

		// Exist checks if a key is in bloom filter
		Exist([]byte) bool

		// Bytes returns the bytes of bloom filter
		Bytes() []byte
	}
)

// NewBloomFilterLegacy returns a legacy new bloom filter
// it does not support NumElements()
func NewBloomFilterLegacy(m, h uint) (BloomFilter, error) {
	switch m {
	case 2048:
		return newBloom2048(h)
	default:
		return nil, errors.Errorf("bloom filter size %d not supported", m)
	}
}

// BloomFilterFromBytesLegacy constructs a bloom filter from bytes
func BloomFilterFromBytesLegacy(b []byte, m, h uint) (BloomFilter, error) {
	switch m {
	case 2048:
		return bloom2048FromBytes(b, h)
	default:
		return nil, errors.Errorf("bloom filter size %d not supported", m)
	}
}

// NewBloomFilter returns a new bloom filter
func NewBloomFilter(m, h uint64) (BloomFilter, error) {
	return newBloomMbits(m, h)
}

// BloomFilterFromBytes constructs a bloom filter from bytes
func BloomFilterFromBytes(buf []byte) (BloomFilter, error) {
	return bloomMbitsFromBytes(buf)
}
