package keypair

import (
	"crypto/ed25519"
	"encoding/base64"
)

type Ed25519KeyPair struct {
	pkey *ed25519.PublicKey
	skey *ed25519.PrivateKey
}

func (k *Ed25519KeyPair) Sign(digest []byte) ([]byte, error) {
	return ed25519.Sign(*k.skey, digest), nil
}

func (k *Ed25519KeyPair) ToJWK() *JsonWebKey {
	return &JsonWebKey{
		Kty: "OKP",
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(*k.pkey),
	}
}

type Ed25519KeyPairFactory struct{}

func (f *Ed25519KeyPairFactory) New() KeyPair {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return &Ed25519KeyPair{
		pkey: &pub,
		skey: &priv,
	}
}

func NewEd25519KeyPairFactory() KeyPairFactory {
	return &Ed25519KeyPairFactory{}
}
