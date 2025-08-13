package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBLS12381CompatibilityEth(t *testing.T) {
	r := require.New(t)
	t.Run("privateKeyAndPublicKey", func(t *testing.T) {
		cases := []struct {
			ikm        string
			privateKey string
			publicKey  string
		}{
			{ikm: "1a9ef39562fb483911451758f0d381bfb5d35081cf850433173a004049aa7552",
				privateKey: "3794dfaa739d26ac8dcd106fdf637f8aef5d5dde20facd0da7ba1dcf6b1a572b",
				publicKey:  "966a25e30fc3ba7bac1abe1a04b757a80ec21e8da9907674c47d471c033d95014a871fdac1d4f3393c05d64f72243511"},
			{ikm: "cf0d37ca13a6a0ce67763a9f32accd016d68ab6975c03c44e6e5621aca094164",
				privateKey: "4bebb18e9497002a0ba81d1a5ce1b3f9b9fc8527c8a46ff0a0219f3b3aebee5b",
				publicKey:  "937243f9c1e6b1f99fae5de153f0571e2d6b63320b409f3df87c52fbb24ce7b9c77c0330a8730ea89fc3bb2653607bf9"},
			{ikm: "9ee12ee0ec4729cc58c452269078fc17eee71947add87515557f5e0693148768",
				privateKey: "0d798eac4b2da3c68830f33f8a3f08cd57ecaefc73e6a4e7004666199b3451f3",
				publicKey:  "83a53e77e141d498197c4dcefc857d3b6e0fa06f7b4ae1c08fb3aae831c75e45a87210a162ee9e516c96d10c8ec0a51f"},
			{ikm: "e719eacb17e6a4f05519cdaf1f52eab3cfbd574a557467943a4c82fc38466cb6",
				privateKey: "2adf2d6a14f5ba2104b5a70e8da5c1a60ac249d1249db68a83519ce8b0eeef45",
				publicKey:  "8c68b3646579d510ed2e9716de5f70a96d2a97e8bd236dcfe8ce796aba12d18227030c9e1f692990a812813ca8b48364"},
			{ikm: "cb76b37510b45900b2f9c5f1ad9979a7522eb64a6638f128e740c909f0932cf0",
				privateKey: "12fdede47dc18299ce9db67fb2b67182fc02727934b10ebfae122b4f8d0aebfd",
				publicKey:  "acc3d3d71b6c3cb31b7fa5c37e2d1eb2549cb42722e653a1ef483f8b74ca37903dc5bd0e8ef72eda8c424b304ffbd316"},
		}
		for _, c := range cases {
			// generate private key from ikm
			ikm, err := hex.DecodeString(c.ikm)
			r.NoError(err, "decoding ikm should not error")
			priv, err := GenerateBLS12381PrivateKey(ikm)
			r.NoError(err, "private key generation should not error")
			// check private key
			r.Equal(c.privateKey, priv.HexString(), "private key hex string should match expected")
			expectBytes, err := hex.DecodeString(c.privateKey)
			r.NoError(err, "decoding expected private key should not error")
			r.Equal(expectBytes, priv.Bytes(), "private key bytes should match expected")
			// derive and check public key
			pub := priv.PublicKey()
			r.Equal(c.publicKey, pub.HexString(), "public key hex string should match expected")
			expectPubBytes, err := hex.DecodeString(c.publicKey)
			r.NoError(err, "decoding expected public key should not error")
			r.Equal(expectPubBytes, pub.Bytes(), "public key bytes should match expected")
			// create private key from bytes
			privFromBytes, err := BLS12381PrivateKeyFromBytes(priv.Bytes())
			r.NoError(err, "creating private key from bytes should not error")
			r.Equal(priv.HexString(), privFromBytes.HexString(), "private key from bytes hex string should match")
			r.Equal(priv.Bytes(), privFromBytes.Bytes(), "private key from bytes should match")
			// create public key from bytes
			pubFromBytes, err := BLS12381PublicKeyFromBytes(pub.Bytes())
			r.NoError(err, "creating public key from bytes should not error")
			r.Equal(pub.HexString(), pubFromBytes.HexString(), "public key from bytes hex string should match")
			r.Equal(pub.Bytes(), pubFromBytes.Bytes(), "public key from bytes should match")
		}
	})
	t.Run("signature", func(t *testing.T) {
		cases := []struct {
			privateKey string
			msg        string
			signature  string
		}{
			{privateKey: "2d7afd069bf2b4c8ce02e8104e61e2db23adeb448e9698c43e84a0a797002892",
				msg:       "a4cd490a0924dc10aaa96c352d6513264d6cfabb22b167ddfcd13ca293cc2867",
				signature: "a7f2ff330aa2b70e9ae3ff8418384815e6ed76e25b315894bdee012a583ed98406fa62b206edf76f0b32d3cf04c60bf100fd16d3a777a2b348104f65c5e0f57add8af17f0c20f343834e36f8f5ffccbf6d5844919752d86b9c554a238444aa5c"},
			{privateKey: "629e123505db736cf74de16cb55b155ef72f03bdc171764c77eedc72b8f8215b",
				msg:       "e4911fdb384a736a06268083c87d576a296c0232835ac80e478f4cf7a7d0610e",
				signature: "84be624cb08e082a95c314008520f450707064a30aeb7a1c507f0c0b779397f25c0f402adefb346075e2bd4097a2fd631454dfb31c9715b7d478600b340c57053da2acf09a0247e8b56060721954f5727cee2ebe8381eac1e256be8ca5b94251"},
		}
		for _, c := range cases {
			// sign the message
			privKeyBytes, err := hex.DecodeString(c.privateKey)
			r.NoError(err, "decoding private key should not error")
			priv, err := BLS12381PrivateKeyFromBytes(privKeyBytes)
			r.NoError(err, "private key generation should not error")
			msgBytes, err := hex.DecodeString(c.msg)
			r.NoError(err, "decoding message should not error")
			sig, err := priv.Sign(msgBytes)
			r.NoError(err, "signing should not error")
			r.Equal(c.signature, hex.EncodeToString(sig), "signature hex string should match expected")
			// verify the signature
			pub := priv.PublicKey()
			r.True(pub.Verify(msgBytes, sig), "signature should be valid")
		}
	})
	t.Run("aggregateSignature", func(t *testing.T) {
		cases := []struct {
			signatures []string
			aggregate  string
		}{
			{
				signatures: []string{
					"aed6ed66be49f11bed468f79f5a78aeace27b2ac54f86376ef002dba97bce37ebdf1d9e89f5b2615d13a5f99d6c3db47101cb38d994a0d2ab7497325e890bcff1be500b55be25ff5d1cfc75db5e5d92fab362a2488708a5320d8fd51c0a02601",
					"9943fab4f36a5eedc81b3b18ba294f846c53099d2b58ef00cb2f87b9fbe786bb206c72fa43b59bc46e6d3536b57e14f00b0f9e4d01ac88397bbf60f8357369d38e0340e72b80b778b63899c1f603df6371e26d7262c7818c01eb020c5a580018",
					"b04ae4d58b4eaee0c6d2b76e8fcfde6a6133a413cfd8e2b8e632bb7e52e75d3963ac8a2bce84a7ebbd0476c4fdeb53041992c04facd5f4ecdd0dffbad6303e2c76dcb59593aa231c780632600d4bd6bba08a68715365c82b09c6824b099bb647",
					"88b79c9e5cf6e87cd4e77e14586e00086b538a67557baeeb4baef369afce6978d074f57ea47e6cddb9bd43253eca1f3e029fdac240719eb965d9c2cfbeb5c20c8048f79f1dfb352c6846f54b4135bce1147185f6631d258268c6733cab223a78",
					"a41009b442ff28ff1423195b003fd4300ff3e0c1863be132f211b0fce3512ccf52b0f3e8ffc6120040b856df45363a0803fdfe99f10b7bfffdd55ac35b089a3de5f32211c2a55363b02062ff6c0b850dc9c47606012d0add3b9e4070cd7ebb0e",
				},
				aggregate: "88c9cf19801cd15672f16fb23612d36ae5aaf6eba8eb01f11e66b8f42b152e516c2e1466338e7383a5f7a8cf88ad3ef117866e3fdd96844e31b4b35808718290c181cdbdf33d6deaa9f9a815eaed3a6d900fb14ee8de5608a12906b76cb3d476",
			},
		}
		for _, c := range cases {
			// aggregate the signatures
			var sigs [][]byte
			for _, s := range c.signatures {
				sigBytes, err := hex.DecodeString(s)
				r.NoError(err, "decoding signature should not error")
				sigs = append(sigs, sigBytes)
			}
			aggSig, err := BLSAggregateSignature(sigs)
			r.NoError(err, "aggregating signatures should not error")
			r.Equal(c.aggregate, hex.EncodeToString(aggSig), "aggregate signature hex string should match expected")
		}
	})
}
