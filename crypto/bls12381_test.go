package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/iotexproject/go-pkgs/hash"
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
			msg        string
			pubkeys    []string
			signatures []string
			aggregate  string
		}{
			{
				msg: "813eab1bc4999dda23dd7e3d556d15fb02c23c9cce59fae5156d97ff453915a9",
				pubkeys: []string{
					"ad5b9a812c121e0b06b52ce2ff3d1879fc4e8386d3f7aa2926b25d40d966031f13f98ff804a4e2ee188c9d9fc815a1d2",
					"a06d81d1bc33d6eaa8d5254d17e8521d26887077a55f00358daac76629ef662f0ea48b05ac3f46fbed2f18c909dd6526",
					"8d4ac523a5ec3dfbee4d1ed69c82f50ae13c9764a42dbf1f0530e19909a5baed6c2a0813e3fd7720ddf3980172fb477b",
					"93b7f26176aa97f76476396ed8b695c2e0f559ad7bed50233e542f604510d30c4fdd42a8df78062e36da7db5c86a0252",
					"84308af049bbc88e33a8a6f1bb5d92039c8f8106b1adab34c22c04864f8ee1fa530676c00bbcffd65d18017452974493",
				},
				signatures: []string{
					"a60e5fa25333fd52875cd56715387c673fb8514284f71ef8fd24bc5f3446aa9f9d7017d594430da105f1d2030ac802eb000976682ed19baa04e649069905561003a430a193f430d10c3f8cc4cff6ab81821b4c4d4ec93d964938da472c474023",
					"965c555db62c4056340f819c7b34ef93999c50ea508909aa266d21e7bcfb43e31a7a5f0815d207742703af2a6ed1d481081f7e0edccb25b0974cac99c6a8d6c73b70c3d219538d3578281878f309b960a214d9482a874627c3c7368548f28637",
					"ab7c0c75923974160959bfd3b3c1856feec7fb5e998d9b8fa93f132774c9017a12181fad340a642cb6022556b5d65f0710b0ac2337655a980e55cdfe0d90cdea4832c5d62ff19a5da196af67df6b87ca0d877d61ddc6fb9d2d7ccff4a5649a52",
					"8e1bbe115f6d4209928561fd667fca15a950e3d1b0fa8299e9cbc592a93ae439f26ea26f448451e1637689d19139e66c00770bdce20fb82869865a709f868dc77307a23862b5267537c8e5f5a7fd8d91580d57da1e57458fc805834311c79871",
					"8ead132c26c914953dd619947ee6b6a80caa1dbe4ec0bf832819cc2a2d7cac14db68d10ad88246e6486b6832e00e3b7100550402a38b837498358b96c23949c5ddd47cf3532e6a958d8187c34723b35ec79b8f9fb213a56204c91b9955f8d2ca",
				},
				aggregate: "a226c93260a62bc95dbddfe81b128f943d8db79931ca08d46aa7fb6720ea639fe6de056ba4a24a79ccf796eac974d86106353141aa6bdb6c79b53987b9823ab5ecffb2b9e1f5cf88f42b2e62136ecb867af9894c067ba7bb66981f043b4ceb38",
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
			aggSig, err := NewBLSAggregateSignature(sigs)
			r.NoError(err, "aggregating signatures should not error")
			r.Equal(c.aggregate, aggSig.HexString(), "aggregate signature hex string should match expected")
			// from bytes
			aggSigFromBytes, err := BLSAggregateSignatureFromBytes(aggSig.Bytes())
			r.NoError(err, "creating aggregate signature from bytes should not error")
			r.Equal(aggSig.HexString(), aggSigFromBytes.HexString(), "aggregate signature from bytes hex string should match")
			r.Equal(aggSig.Bytes(), aggSigFromBytes.Bytes(), "aggregate signature from bytes should match")
			// verify the aggregate signature
			var pubKeys []*BLS12381PublicKey
			for _, pk := range c.pubkeys {
				pkBytes, err := hex.DecodeString(pk)
				r.NoError(err, "decoding public key should not error")
				pubKey, err := BLS12381PublicKeyFromBytes(pkBytes)
				r.NoError(err, "creating public key from bytes should not error")
				pubKeys = append(pubKeys, pubKey)
			}
			msgBytes, err := hex.DecodeString(c.msg)
			r.NoError(err, "decoding message should not error")
			r.True(aggSig.Verify(pubKeys, msgBytes), "aggregate signature should be valid")
		}
	})
}

// BenchmarkBLS12381Sign benchmarks the BLS12381 signing operation
func BenchmarkBLS12381Sign(b *testing.B) {
	// Generate a test private key
	ikm := make([]byte, 32)
	for i := range ikm {
		ikm[i] = byte(i)
	}

	priv, err := GenerateBLS12381PrivateKey(ikm)
	if err != nil {
		b.Fatalf("Failed to generate private key: %v", err)
	}

	// Create a test message
	msg := hash.Hash160b([]byte("test message for benchmarking"))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := priv.Sign(msg[:])
		if err != nil {
			b.Fatalf("Failed to sign message: %v", err)
		}
	}
}

// BenchmarkBLS12381Verify benchmarks the BLS12381 signature verification operation
func BenchmarkBLS12381Verify(b *testing.B) {
	// Generate a test private key
	ikm := make([]byte, 32)
	for i := range ikm {
		ikm[i] = byte(i)
	}

	priv, err := GenerateBLS12381PrivateKey(ikm)
	if err != nil {
		b.Fatalf("Failed to generate private key: %v", err)
	}

	pub := priv.PublicKey()

	// Create a test message and sign it
	msg := hash.Hash160b([]byte("test message for benchmarking"))
	sig, err := priv.Sign(msg[:])
	if err != nil {
		b.Fatalf("Failed to sign message: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !pub.Verify(msg[:], sig) {
			b.Fatalf("Failed to verify signature")
		}
	}
}

// BenchmarkBLSAggregateSignature benchmarks the BLS signature aggregation operation
func BenchmarkBLSAggregateSignature(b *testing.B) {
	// Generate multiple signatures for aggregation
	numSigs := 24
	var signatures [][]byte
	msg := hash.Hash160b([]byte("test message for benchmarking"))

	for i := 0; i < numSigs; i++ {
		ikm := make([]byte, 32)
		for j := range ikm {
			ikm[j] = byte(i*32 + j)
		}

		priv, err := GenerateBLS12381PrivateKey(ikm)
		if err != nil {
			b.Fatalf("Failed to generate private key %d: %v", i, err)
		}

		sig, err := priv.Sign(msg[:])
		if err != nil {
			b.Fatalf("Failed to sign message %d: %v", i, err)
		}

		signatures = append(signatures, sig)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := NewBLSAggregateSignature(signatures)
		if err != nil {
			b.Fatalf("Failed to aggregate signatures: %v", err)
		}
	}
}

// BenchmarkBLSAggregateVerify benchmarks the BLS aggregate signature verification operation
func BenchmarkBLSAggregateVerify(b *testing.B) {
	// Generate multiple key pairs and signatures for aggregate verification
	numSigs := 24
	var signatures [][]byte
	var pubKeys []*BLS12381PublicKey
	msg := hash.Hash160b([]byte("test message for benchmarking"))

	for i := 0; i < numSigs; i++ {
		ikm := make([]byte, 32)
		for j := range ikm {
			ikm[j] = byte(i*32 + j)
		}

		priv, err := GenerateBLS12381PrivateKey(ikm)
		if err != nil {
			b.Fatalf("Failed to generate private key %d: %v", i, err)
		}

		pub := priv.PublicKey()
		pubKeys = append(pubKeys, pub)

		sig, err := priv.Sign(msg[:])
		if err != nil {
			b.Fatalf("Failed to sign message %d: %v", i, err)
		}

		signatures = append(signatures, sig)
	}

	aggSign, err := NewBLSAggregateSignature(signatures)
	if err != nil {
		b.Fatalf("Failed to aggregate signatures: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		valid := aggSign.Verify(pubKeys, msg[:])
		if !valid {
			b.Fatalf("Aggregate signature verification failed")
		}
	}
}
