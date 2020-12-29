// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package bloom

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBloom2048b_setBit(t *testing.T) {
	require := require.New(t)

	f := &bloom2048b{numHash: 3}
	key := make(map[int]bool)
	for i := 0; i < 512; i++ {
		pos := rand.Intn(2048)
		key[pos] = true
		f.setBit(byte(pos), byte(pos>>8))
	}

	for i := 0; i < 2048; i++ {
		_, ok := key[i]
		require.Equal(ok, f.chkBit(byte(i), byte(i>>8)))
	}
}
