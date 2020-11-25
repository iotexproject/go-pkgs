// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotexproject/go-pkgs/hash"
)

func TestSecp256k1(t *testing.T) {
	require := require.New(t)

	sk, err := newSecp256k1PrvKey()
	require.NoError(err)
	defer sk.Zero()
	require.Equal(secp256prvKeyLength, len(sk.Bytes()))
	pk := sk.PublicKey()
	require.Equal(secp256pubKeyLength, len(pk.Bytes()))
	nsk, err := newSecp256k1PrvKeyFromBytes(sk.Bytes())
	require.NoError(err)
	require.Equal(sk, nsk)
	npk, err := newSecp256k1PubKeyFromBytes(pk.Bytes())
	require.NoError(err)
	require.Equal(pk, npk)
	_, ok := sk.EcdsaPrivateKey().(*ecdsa.PrivateKey)
	require.True(ok)
	_, ok = pk.EcdsaPublicKey().(*ecdsa.PublicKey)
	require.True(ok)

	h := hash.Hash256b([]byte("test secp256k1 signature så∫jaç∂fla´´3jl©˙kl3∆˚83jl≈¥fjs2"))
	sig, err := sk.Sign(h[:])
	require.NoError(err)
	require.True(sig[Secp256k1SigSize] == 0 || sig[Secp256k1SigSize] == 1)
	require.True(pk.Verify(h[:], sig))
	for i := 0; i < len(sig)-1; i++ {
		sig[i]--
		require.False(pk.Verify(h[:], sig))
		sig[i]++
	}
	require.True(pk.Verify(h[:], sig))

	// test recover pubkey
	npk, err = RecoverPubkey(h[:], sig)
	require.NoError(err)
	require.Equal(pk, npk)

	sig[Secp256k1SigSize] += 27
	require.True(pk.Verify(h[:], sig))

	sig[Secp256k1SigSize] = 2
	require.False(pk.Verify(h[:], sig))

	// test Ethereum signature with recovery id >= 27
	ha, _ := hex.DecodeString("f93a97fae37fdadab6d49b74e3f3e4bee707ea2f007e08007bcc356cb283665b")
	sig, _ = hex.DecodeString("5595906a47dfc107a78cc48b500f89ab2dec545ba86578295aed4a260ce9a98b335924e86f683832e313f1a5dda7826d9b59caf40dd22ce92716420a367dfaec1c")
	require.EqualValues(28, sig[Secp256k1SigSize])
	pk, err = RecoverPubkey(ha, sig)
	require.NoError(err)
	require.EqualValues(28, sig[Secp256k1SigSize])
	require.Equal("53fbc28faf9a52dfe5f591948a23189e900381b5", hex.EncodeToString(pk.Hash()))

}
