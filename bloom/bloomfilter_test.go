// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package bloom

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBloomFilter(t *testing.T) {
	require := require.New(t)

	f1, err := newBloom2048(3)
	require.NoError(err)
	f2, err := newBloomMbits(256, 4)
	require.NoError(err)
	f3, err := newBloomMbits(2048, 3)
	require.NoError(err)
	f4, err := newBloomMbits(500000, 5)
	require.NoError(err)

	for _, f := range []BloomFilter{
		f1, f2, f3, f4,
	} {
		// insert 1/8 capacity
		count := f.Size() >> 3
		var key [][]byte
		for i := uint64(0); i < count; i++ {
			k := make([]byte, 8)
			require.NoError(binary.Read(rand.Reader, binary.BigEndian, k))
			f.Add(k)
			key = append(key, k)
		}

		// verify keys exist
		for _, k := range key {
			require.True(f.Exist(k[:]))
		}

		// empty key does not exist
		require.False(f.Exist(nil))

		// random keys should not exist
		for i := 0; i < 2; i++ {
			k := make([]byte, 8)
			require.NoError(binary.Read(rand.Reader, binary.BigEndian, k))
			require.False(f.Exist(k[:]))
		}
	}
}
