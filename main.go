package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

type Ed25519KeyPair struct {
	PublicKey  *ed25519.PublicKey
	PrivateKey *ed25519.PrivateKey
}

type JsonWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

type CredentialSubject struct {
	ID     string `json:"id"`
	Random string `json:"random"`
}

type VerifiableCredential struct {
	Context           []string          `json:"@context"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

func generateEd25519KeyPair() (*Ed25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return &Ed25519KeyPair{
		PublicKey:  &pub,
		PrivateKey: &priv,
	}, nil
}

func generateRandomCredential(issuer string, holder string) (*VerifiableCredential, error) {
	randb := make([]byte, 32)
	_, err := rand.Read(randb)
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(randb)

	return &VerifiableCredential{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Type:    []string{"VerifiableCredential"},
		Issuer:  issuer,
		CredentialSubject: CredentialSubject{
			ID:     holder,
			Random: encoded,
		},
	}, nil
}

func main() {
	nStr := os.Args[1]
	if nStr == "" {
		panic("Please provide the number of key pairs to generate")
	}
	n, err := strconv.Atoi(nStr)
	if err != nil {
		panic("Please provide a valid number")
	}

	issuer := os.Args[2]
	if issuer == "" {
		panic("Please provide the issuer")
	}

	holder := os.Args[3]
	if holder == "" {
		panic("Please provide the holder")
	}

	// generate key pair
	kp, err := generateEd25519KeyPair()
	if err != nil {
		panic(err)
	}

	// check if jwk directory exists
	if _, err := os.Stat("tmp"); os.IsNotExist(err) {
		os.Mkdir("tmp", 0755)
	}
	if _, err := os.Stat("tmp/jwk"); os.IsNotExist(err) {
		os.Mkdir("tmp/jwk", 0755)
	}

	// save jwk to file
	jwk := JsonWebKey{
		Kid: "did:web:localhost%3A8081#key-0",
		Kty: "OKP",
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   base64.URLEncoding.EncodeToString(*kp.PublicKey),
	}
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(fmt.Sprintf("tmp/jwk/%s.json", jwk.Kid), jwkBytes, 0644)
	if err != nil {
		panic(err)
	}

	// generate n random verifiable credential
	f, err := os.Create("tmp/jwt.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for i := 0; i < n; i++ {
		vc, err := generateRandomCredential(issuer, holder)
		if err != nil {
			panic(err)
		}

		// vc to map
		vcMap := map[string]interface{}{}
		vcBytes, err := json.Marshal(vc)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(vcBytes, &vcMap)
		if err != nil {
			panic(err)
		}

		jwt := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(vcMap))
		jwt.Header["kid"] = jwk.Kid

		tokenString, err := jwt.SignedString(*kp.PrivateKey)
		if err != nil {
			panic(err)
		}

		_, err = f.WriteString(tokenString + "\n")
		if err != nil {
			panic(err)
		}
	}
}
