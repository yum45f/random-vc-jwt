package keypair

type KeyPair interface {
	Sign(digest []byte) ([]byte, error)
	ToJWK() *JsonWebKey
}

type KeyPairFactory interface {
	New() KeyPair
}

type JsonWebKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
}
