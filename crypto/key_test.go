// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeypair(t *testing.T) {
	require := require.New(t)

	tests := []struct {
		sk, pk string
	}{
		{
			// p256k1 keypair
			"82a1556b2dbd0e3615e367edf5d3b90ce04346ec4d12ed71f67c70920ef9ac90",
			"04403d3c0dbd3270ddfc248c3df1f9aafd60f1d8e7456961c9ef26292262cc68f0ea9690263bef9e197a38f06026814fc70912c2b98d2e90a68f8ddc5328180a01",
		},
		{
			// p256sm2 keypair
			"308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104202d57ec7da578b98dad465997748ed02af0c69092ad809598073e5a2356c20492a00a06082a811ccf5501822da14403420004223356f0c6f40822ade24d47b0cd10e9285402cbc8a5028a8eec9efba44b8dfe1a7e8bc44953e557b32ec17039fb8018a58d48c8ffa54933fac8030c9a169bf6",
			"3059301306072a8648ce3d020106082a811ccf5501822d03420004223356f0c6f40822ade24d47b0cd10e9285402cbc8a5028a8eec9efba44b8dfe1a7e8bc44953e557b32ec17039fb8018a58d48c8ffa54933fac8030c9a169bf6",
		},
	}

	_, err := HexStringToPublicKey("c248c3df1f9aafd60f1d8e")
	require.Equal(ErrPublicKey, err)
	_, err = HexStringToPrivateKey("7edf5d3b90ce04346ef1d8")
	require.Equal(ErrPrivateKey, err)
	_, err = BytesToPublicKey([]byte{1, 2, 3})
	require.Equal(ErrPublicKey, err)
	_, err = BytesToPrivateKey([]byte{4, 5, 6})
	require.Equal(ErrPrivateKey, err)

	for i, e := range tests {
		sk, err := HexStringToPrivateKey(e.sk)
		require.NoError(err)
		pk, err := HexStringToPublicKey(e.pk)
		require.NoError(err)
		require.Equal(sk.PublicKey(), pk)

		if i == 0 {
			// this is p256k1
			pk2, err := HexStringToPublicKey(e.pk[2:])
			require.NoError(err)
			require.Equal(pk, pk2)
		}

		require.Equal(e.pk, pk.HexString())
		require.Equal(e.sk, sk.HexString())
	}
}

/*
TODO (dustinxie): revise this unit test: don't use address
func TestCompatibility(t *testing.T) {
	require := require.New(t)

	sk, err := crypto.GenerateKey()
	require.NoError(err)
	ethAddr := crypto.PubkeyToAddress(sk.PublicKey)
	nsk := &secp256k1PrvKey{PrivateKey: sk}
	addr, err := address.FromBytes(nsk.PublicKey().Hash())
	require.NoError(err)
	require.Equal(ethAddr.Bytes(), addr.Bytes())
}
*/
