// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package bloom

import (
	"io"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/iotexproject/go-pkgs/byteutil"
	"github.com/iotexproject/go-pkgs/hash"
)

func TestBloomMbits(t *testing.T) {
	require := require.New(t)

	_, err := newBloomMbits(256, 0)
	require.Equal(ErrNumHash, errors.Cause(err))
	_, err = newBloomMbits(256, 256)
	require.Equal(ErrNumHash, errors.Cause(err))

	for _, v := range []struct {
		m, k, n uint64
	}{
		{500, 6, 50},
		{2048, 4, 200},
		{10000, 3, 2000},
	} {
		f, err := newBloomMbits(v.m, v.k)
		require.NoError(err)
		for i := uint64(0); i < v.n; i++ {
			k := hash.Hash256b(byteutil.Uint64ToBytesBigEndian(i))
			f.Add(k[:8])
		}
		require.Equal(v.m, f.Size())
		require.Equal(v.k, f.NumHash())
		require.Equal(v.n, f.NumElements())
		b := f.Bytes()
		require.EqualValues(24+(v.m+63)>>6<<3+32, len(b))

		// decode and verify
		newBF := bloomMbits{}
		err = newBF.FromBytes(b)
		require.NoError(err)
		for i := uint64(0); i < v.n; i++ {
			k := hash.Hash256b(byteutil.Uint64ToBytesBigEndian(i))
			require.True(f.Exist(k[:8]))
		}
		require.Equal(v.m, f.Size())
		require.Equal(v.k, f.NumHash())
		require.Equal(v.n, f.NumElements())
		h := hash.Hash256b(byteutil.Uint64ToBytesBigEndian(v.n))
		k := h[:]
		for i := 0; i < 4; i++ {
			require.False(f.Exist(k[:8]))
			k = k[8:]
		}

		// corrupted hash
		bTmp := make([]byte, len(b))
		copy(bTmp, b)
		bTmp[len(b)-1]++
		err = newBF.FromBytes(bTmp)
		require.Equal(ErrHashMismatch, errors.Cause(err))

		// not enough data
		bTmp = bTmp[1 : len(b)-32]
		h = hash.Hash256b(bTmp)
		bTmp = append(bTmp, h[:]...)
		err = newBF.FromBytes(bTmp)
		require.Equal(io.ErrUnexpectedEOF, errors.Cause(err))

		// verify again
		err = newBF.FromBytes(b)
		require.NoError(err)
		for i := uint64(0); i < v.n; i++ {
			k := hash.Hash256b(byteutil.Uint64ToBytesBigEndian(i))
			require.True(f.Exist(k[:8]))
		}
		require.Equal(v.m, f.Size())
		require.Equal(v.k, f.NumHash())
		require.Equal(v.n, f.NumElements())
		h = hash.Hash256b(byteutil.Uint64ToBytesBigEndian(v.n))
		k = h[:]
		for i := 0; i < 4; i++ {
			require.False(f.Exist(k[:8]))
			k = k[8:]
		}
	}
}
