// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test256sm2(t *testing.T) {
	require := require.New(t)

	sk, err := GenerateKeySm2()
	require.NoError(err)

	sk1, err := newP256sm2PrvKeyFromBytes(sk.Bytes())
	require.NoError(err)
	require.Equal(sk, sk1)

	k, ok := sk.EcdsaPrivateKey().(*P256sm2PrvKey)
	require.True(ok)
	sk2, err := newP256sm2PrvKeyFromD(k.D())
	require.NoError(err)
	require.Equal(sk, sk2)

	pk := sk.PublicKey()
	pk1, err := newP256sm2PubKeyFromBytes(pk.Bytes())
	require.NoError(err)
	require.Equal(pk, pk1)
	require.Equal(20, len(pk.Hash()))
	_, ok = pk.EcdsaPublicKey().(*P256sm2PubKey)
	require.True(ok)

	// test pem
	pwd := "s8fjl*[]>?<"
	require.NoError(WritePrivateKeyToPem("sk.pem", k, pwd))
	defer os.Remove("sk.pem")
	require.NoError(WritePublicKeyToPem("pk.pem", pk.(*P256sm2PubKey), pwd))
	defer os.Remove("pk.pem")
	sk1, err = ReadPrivateKeyFromPem("sk.pem", pwd)
	require.NoError(err)
	require.Equal(sk, sk1)
	pk1, err = ReadPublicKeyFromPem("pk.pem", pwd)
	require.NoError(err)
	require.Equal(pk, pk1)

	// test sign/verify
	msg := []byte("test data to be signed")
	var s []byte
	for i := 0; i < 5; i++ {
		sig, err := sk.Sign(msg)
		require.NoError(err)
		require.EqualValues(0x30, sig[0])
		require.EqualValues(len(sig), sig[1]+2)
		require.Equal(true, sk.PublicKey().Verify(msg, sig))
		require.NotEqual(s, sig)
		s = sig
	}
}
