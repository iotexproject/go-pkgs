// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package bloom

import (
	"math/rand"
	"testing"

	"github.com/iotexproject/go-pkgs/hash"
	"github.com/stretchr/testify/require"
)

func TestNewBloomFilter(t *testing.T) {
	require := require.New(t)

	f, err := NewBloomFilter(1024, 3)
	require.Error(err)
	require.Nil(f)
	f, err = NewBloomFilter(2048, 17)
	require.Error(err)
	require.Nil(f)
}

func TestBloomFilterFromBytes(t *testing.T) {
	require := require.New(t)

	f, err := BloomFilterFromBytes(hash.ZeroHash256[:], 1024, 3)
	require.Error(err)
	require.Nil(f)
	f, err = BloomFilterFromBytes(hash.ZeroHash256[:], 2048, 17)
	require.Error(err)
	require.Nil(f)
	f, err = BloomFilterFromBytes(hash.ZeroHash256[:], 2048, 3)
	require.Error(err)
	require.Nil(f)

	// construct 256-byte slice
	var k [256]byte
	for i := 0; i < 128; i++ {
		r := rand.Intn(256)
		k[r] = byte(256 - r)
	}
	f, err = BloomFilterFromBytes(k[:], 2048, 3)
	require.NoError(err)
	require.Equal(k[:], f.Bytes())
}
