// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package bloom

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"

	"github.com/iotexproject/go-pkgs/byteutil"
	"github.com/iotexproject/go-pkgs/hash"
)

var (
	ErrHashMismatch = errors.New("failed to verify hash")
	ErrNumHash      = errors.New("invalid number of hash functions, expect 0 < k < 256")
)

type bloomMbits struct {
	buckets []uint64 // each bucket houses 64-bit
	m, k, n uint64
	round   uint64 // each round generates 4 x 64-bit key
	rem     int    // k = 4 * round + rem
}

func newBloomMbits(m, k uint64) (BloomFilter, error) {
	if k == 0 || k >= 256 {
		return nil, ErrNumHash
	}

	b := bloomMbits{
		buckets: make([]uint64, (m+63)>>6),
		m:       m,
		k:       k,
		round:   k >> 2,
		rem:     int(k & 3),
	}
	return &b, nil
}

// Size of bloom filter in bits
func (b *bloomMbits) Size() uint64 {
	return b.m
}

// NumHash is the number of hash functions used
func (b *bloomMbits) NumHash() uint64 {
	return b.k
}

// NumElements is the number of elements in the bloom filter
func (b *bloomMbits) NumElements() uint64 {
	return b.n
}

// Add key into bloom filter
func (b *bloomMbits) Add(key []byte) {
	if key == nil {
		return
	}

	var h hash.Hash256
	for i := uint64(0); i < b.round; i++ {
		h = hash.Hash256b(append(key, byteutil.Uint64ToBytesBigEndian(i)...))
		k := h[:]
		for i := 0; i < 4; i++ {
			b.setBit(byteutil.BytesToUint64BigEndian(k))
			k = k[8:]
		}
	}

	if b.rem > 0 {
		h = hash.Hash256b(append(key, byteutil.Uint64ToBytesBigEndian(b.round)...))
		k := h[:]
		for i := 0; i < b.rem; i++ {
			b.setBit(byteutil.BytesToUint64BigEndian(k))
			k = k[8:]
		}
	}
	b.n++
}

// Exist checks if a key is in bloom filter
func (b *bloomMbits) Exist(key []byte) bool {
	if key == nil {
		return false
	}

	var h hash.Hash256
	for i := uint64(0); i < b.round; i++ {
		h = hash.Hash256b(append(key, byteutil.Uint64ToBytesBigEndian(i)...))
		k := h[:]
		for i := 0; i < 4; i++ {
			if b.getBit(byteutil.BytesToUint64BigEndian(k)) == 0 {
				return false
			}
			k = k[8:]
		}
	}

	if b.rem > 0 {
		h = hash.Hash256b(append(key, byteutil.Uint64ToBytesBigEndian(b.round)...))
		k := h[:]
		for i := 0; i < b.rem; i++ {
			if b.getBit(byteutil.BytesToUint64BigEndian(k)) == 0 {
				return false
			}
			k = k[8:]
		}
	}
	return true
}

// Bytes returns the bytes of bloom filter (in Big Endian)
//
//   m:       uint64 x 1
//   k:       uint64 x 1
//   n:       uint64 x 1
//   buckets: []uint64
//   hash:    [32]byte = Hash256b(above)
//
func (b *bloomMbits) Bytes() []byte {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, b.m); err != nil {
		return nil
	}
	if err := binary.Write(buf, binary.BigEndian, b.k); err != nil {
		return nil
	}
	if err := binary.Write(buf, binary.BigEndian, b.n); err != nil {
		return nil
	}
	if err := binary.Write(buf, binary.BigEndian, b.buckets); err != nil {
		return nil
	}

	// append checksum hash
	h := hash.Hash256b(buf.Bytes())
	if err := binary.Write(buf, binary.BigEndian, h); err != nil {
		return nil
	}
	return buf.Bytes()
}

func (b *bloomMbits) setBit(pos uint64) {
	pos %= b.m
	b.buckets[pos>>6] |= 1 << (pos & 0x3f)
}

func (b *bloomMbits) getBit(pos uint64) byte {
	pos %= b.m
	return byte(b.buckets[pos>>6]>>(pos&0x3f)) & 1
}

func bloomMbitsFromBytes(data []byte) (BloomFilter, error) {
	// last 32 bytes is hash of preceding data
	dataLength := len(data) - 32
	wantedHash := hash.BytesToHash256(data[dataLength:])
	actualHash := hash.Hash256b(data[:dataLength])
	if actualHash != wantedHash {
		return nil, errors.Wrapf(ErrHashMismatch, "wanted = %x, actual = %x", wantedHash, actualHash)
	}

	// read m, n, k
	var m, k, n uint64
	buf := bytes.NewBuffer(data[:dataLength])
	if err := binary.Read(buf, binary.BigEndian, &m); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &k); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.BigEndian, &n); err != nil {
		return nil, err
	}

	buckets := make([]uint64, (m+63)>>6)
	if err := binary.Read(buf, binary.BigEndian, buckets); err != nil {
		return nil, err
	}

	return &bloomMbits{
		buckets: buckets,
		m:       m,
		k:       k,
		n:       n,
		round:   k >> 2,
		rem:     int(k & 3),
	}, nil
}
