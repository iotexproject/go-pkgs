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
	// BloomFilter interface
	BloomFilter interface {
		// Add 32-byte key into bloom filter
		Add(hash.Hash256)
		// Exist checks if a key is in bloom filter
		Exist(hash.Hash256) bool
		// Bytes returns the bytes of bloom filter
		Bytes() []byte
		// SetBytes copies the bytes into bloom filter
		SetBytes([]byte) error
	}
)

// NewBloomFilter returns a new bloom filter
func NewBloomFilter(m, h int) (BloomFilter, error) {
	if h <= 0 {
		return nil, errors.New("need a positive number of hash functions")
	}
	switch m {
	case 2048:
		if h <= 0 || h > 16 {
			return nil, errors.New("expecting 0 < number of hash functions <= 16")
		}
		return &bloom2048b{numHash: h}, nil
	default:
		return nil, errors.Errorf("bloom filter size %d not supported", m)
	}
}

// BloomFilterFromBytes constructs a bloom filter from bytes
func BloomFilterFromBytes(b []byte, m, h int) (BloomFilter, error) {
	f, err := NewBloomFilter(m, h)
	if err != nil {
		return nil, err
	}
	if err := f.SetBytes(b); err != nil {
		return nil, err
	}
	return f, nil
}
