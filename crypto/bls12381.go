package crypto

import (
	"crypto/subtle"
	"encoding/hex"

	"github.com/pkg/errors"
	blst "github.com/supranational/blst/bindings/go"
)

const (
	// BLSSecretKeyLength is the length of a BLS secret key in bytes
	BLSSecretKeyLength = 32
	// BLSPubkeyLength is the length of a BLS public key in bytes
	BLSPubkeyLength = 48
	// BLSAggregateSignatureLength is the length of a BLS aggregate signature in bytes
	BLSAggregateSignatureLength = 96
)

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

type (
	blstPublicKey          = blst.P1Affine
	blstSignature          = blst.P2Affine
	blstAggregateSignature = blst.P2Aggregate
	blstAggregatePublicKey = blst.P1Aggregate
)

type (
	// BLS12381PrivateKey represents a BLS12381 private key
	BLS12381PrivateKey struct {
		p *blst.SecretKey
	}
	// BLS12381PublicKey represents a BLS12381 public key
	BLS12381PublicKey struct {
		p *blstPublicKey
	}
	// BLSAggregateSignature represents an aggregated BLS signature
	BLSAggregateSignature struct {
		p *blstSignature
	}
)

// GenerateBLS12381PrivateKey generates a new BLS12381 private key from the given input key material (ikm).
func GenerateBLS12381PrivateKey(ikm []byte) (*BLS12381PrivateKey, error) {
	if len(ikm) < 32 {
		return nil, errors.Wrapf(ErrPrivateKey, "input key material must be at least 32 bytes, got %d bytes", len(ikm))
	}
	priv := &BLS12381PrivateKey{
		p: blst.KeyGen(ikm),
	}
	if IsZero(priv.p.Serialize()) {
		return nil, errors.Wrapf(ErrPrivateKey, "private key generation failed, resulting key is zero")
	}
	return priv, nil
}

// BLS12381PrivateKeyFromBytes creates a BLS12381 private key from the given byte slice.
func BLS12381PrivateKeyFromBytes(b []byte) (*BLS12381PrivateKey, error) {
	if len(b) != BLSSecretKeyLength {
		return nil, errors.Wrapf(ErrPrivateKey, "invalid private key length: got %d, want %d", len(b), BLSSecretKeyLength)
	}
	if IsZero(b) {
		return nil, errors.Wrapf(ErrPrivateKey, "private key is zero")
	}
	sk := new(blst.SecretKey).Deserialize(b)
	if sk == nil {
		return nil, errors.Wrapf(ErrPrivateKey, "invalid private key")
	}
	return &BLS12381PrivateKey{p: sk}, nil
}

// Bytes returns the byte representation of the BLS12381 private key.
func (k *BLS12381PrivateKey) Bytes() []byte {
	return k.p.Serialize()
}

// HexString returns the hexadecimal string representation of the BLS12381 private key.
func (k *BLS12381PrivateKey) HexString() string {
	return hex.EncodeToString(k.Bytes())
}

// Sign signs the given message using the BLS12381 private key.
func (k *BLS12381PrivateKey) Sign(msg []byte) ([]byte, error) {
	signature := new(blstSignature).Sign(k.p, msg, dst)
	return signature.Compress(), nil
}

// PublicKey returns the public key corresponding to the BLS12381 private key.
func (k *BLS12381PrivateKey) PublicKey() *BLS12381PublicKey {
	return &BLS12381PublicKey{
		p: new(blstPublicKey).From(k.p),
	}
}

// Zero clears the BLS12381 private key, effectively zeroizing it.
func (k *BLS12381PrivateKey) Zero() {
	k.p.Zeroize()
}

// BLS12381PublicKeyFromBytes creates a BLS12381 public key from the given byte slice.
func BLS12381PublicKeyFromBytes(b []byte) (*BLS12381PublicKey, error) {
	if len(b) != BLSPubkeyLength {
		return nil, errors.Wrapf(ErrPublicKey, "invalid public key length: got %d, want %d", len(b), BLSPubkeyLength)
	}
	pk := new(blstPublicKey).Uncompress(b)
	if pk == nil {
		return nil, errors.Wrapf(ErrPublicKey, "invalid public key")
	}
	if !pk.KeyValidate() {
		return nil, errors.Wrapf(ErrPublicKey, "invalid public key, key validation failed")
	}
	return &BLS12381PublicKey{p: pk}, nil
}

// Bytes returns the byte representation of the BLS12381 public key.
func (k *BLS12381PublicKey) Bytes() []byte {
	return k.p.Compress()
}

// HexString returns the hexadecimal string representation of the BLS12381 public key.
func (k *BLS12381PublicKey) HexString() string {
	return hex.EncodeToString(k.Bytes())
}

// Verify verifies the given signature against the message using the BLS12381 public key.
func (k *BLS12381PublicKey) Verify(msg []byte, sig []byte) bool {
	signature := new(blstSignature).Uncompress(sig)
	if signature == nil {
		return false
	}
	return signature.Verify(true, k.p, false, msg, dst)
}

// NewBLSAggregateSignature aggregates multiple BLS signatures into a single signature.
func NewBLSAggregateSignature(sigs [][]byte) (*BLSAggregateSignature, error) {
	signature := new(blstAggregateSignature)
	valid := signature.AggregateCompressed(sigs, true)
	if !valid {
		return nil, errors.Wrapf(ErrSignature, "provided signatures fail the group check and cannot be compressed")
	}
	return &BLSAggregateSignature{p: signature.ToAffine()}, nil
}

// BLSAggregateSignatureFromBytes creates a BLS aggregate signature from the given byte slice.
func BLSAggregateSignatureFromBytes(b []byte) (*BLSAggregateSignature, error) {
	if len(b) != BLSAggregateSignatureLength {
		return nil, errors.Wrapf(ErrSignature, "invalid aggregate signature length: got %d, want %d", len(b), BLSAggregateSignatureLength)
	}
	p := new(blstSignature).Uncompress(b)
	if p == nil {
		return nil, errors.Wrapf(ErrSignature, "invalid aggregate signature")
	}
	return &BLSAggregateSignature{p: p}, nil
}

// Bytes returns the byte representation of the BLS aggregate signature.
func (s *BLSAggregateSignature) Bytes() []byte {
	return s.p.Compress()
}

// HexString returns the hexadecimal string representation of the BLS aggregate signature.
func (s *BLSAggregateSignature) HexString() string {
	return hex.EncodeToString(s.Bytes())
}

// Verify verifies the aggregate signature against the given public keys and message.
func (s *BLSAggregateSignature) Verify(pubKeys []*BLS12381PublicKey, msg []byte) bool {
	blstPubkeys := make([]*blstPublicKey, len(pubKeys))
	for i, pubKey := range pubKeys {
		blstPubkeys[i] = pubKey.p
	}
	return s.p.FastAggregateVerify(true, blstPubkeys, msg, dst)
}

// IsZero checks if the given byte slice is all zeros in constant time.
func IsZero(sKey []byte) bool {
	b := byte(0)
	for _, s := range sKey {
		b |= s
	}
	return subtle.ConstantTimeByteEq(b, 0) == 1
}
