package keypair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
)

type ECP256KeyPair struct {
	pkey *ecdsa.PublicKey
	skey *ecdsa.PrivateKey
}

func (k *ECP256KeyPair) Sign(digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.skey, digest)
	if err != nil {
		return nil, err
	}

	// According to RFC7515 A.3.1, the (json web) signature is
	// the concatenation of the two integers R and S.
	// So we return this instead of the DER encoding.
	return append(r.Bytes(), s.Bytes()...), nil
}

func (k *ECP256KeyPair) ToJWK() *JsonWebKey {
	return &JsonWebKey{
		Kty: "EC",
		Alg: "ES256",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(k.pkey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(k.pkey.Y.Bytes()),
	}
}

type ECP256KeyPairFactory struct{}

func (f *ECP256KeyPairFactory) New() KeyPair {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &ECP256KeyPair{
		pkey: &priv.PublicKey,
		skey: priv,
	}
}

func NewECP256KeyPairFactory() KeyPairFactory {
	return &ECP256KeyPairFactory{}
}
