package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yum45f/random-vc-jwt/keypair"
)

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

type KeyAlg int

const (
	P256 KeyAlg = iota
	Ed25519
)

func main() {
	flag.Parse()
	nStr := flag.Arg(1)
	if nStr == "" {
		panic("Please provide the number of key pairs to generate")
	}
	n, err := strconv.Atoi(nStr)
	if err != nil {
		panic("Please provide a valid number")
	}

	issuer := flag.Arg(2)
	if issuer == "" {
		panic("Please provide the issuer URI")
	}

	subject := flag.Arg(3)
	if subject == "" {
		panic("Please provide the subject URI")
	}

	algstr := flag.String("alg", "EdDSA", "Algorithm")
	alg := Ed25519
	switch *algstr {
	case "ed25519":
		alg = Ed25519
	case "p256":
		alg = P256
	default:
		panic("Invalid algorithm")
	}

	// generate key pair
	var kp keypair.KeyPair
	switch alg {
	case P256:
		kp = keypair.NewECP256KeyPairFactory().New()
	case Ed25519:
		kp = keypair.NewEd25519KeyPairFactory().New()
	}

	// check if jwk directory exists
	if _, err := os.Stat("tmp"); os.IsNotExist(err) {
		os.Mkdir("tmp", 0755)
	}
	if _, err := os.Stat("tmp/jwk"); os.IsNotExist(err) {
		os.Mkdir("tmp/jwk", 0755)
	}

	// save jwk to file
	jwk := kp.ToJWK()
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(append([]byte(jwk.X), []byte(jwk.Y)...))
	err = os.WriteFile(fmt.Sprintf("tmp/jwk/%s.json", digest), jwkBytes, 0644)
	if err != nil {
		panic(err)
	}

	jwts := []string{}
	for i := 0; i < n; i++ {
		vc, err := generateRandomCredential(issuer, subject)
		if err != nil {
			panic(err)
		}

		vcb, err := json.Marshal(vc)
		if err != nil {
			panic(err)
		}

		headerb, err := json.Marshal(map[string]interface{}{
			"alg": jwk.Alg,
			"kty": jwk.Kty,
			"crv": jwk.Crv,
		})
		if err != nil {
			panic(err)
		}

		header := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(headerb)
		payload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(vcb)

		// sign
		sig, err := kp.Sign([]byte(strings.Join([]string{header, payload}, ".")))
		jwt := fmt.Sprintf("%s.%s.%s", header, payload, base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sig))
		jwts = append(jwts, jwt)
		if err != nil {
			panic(err)
		}
	}

	// generate n random verifiable credential
	f, err := os.Create("tmp/vc-jwts.txt")
	if err != nil {
		panic(err)
	}

	for _, jwt := range jwts {
		_, err := f.WriteString(jwt + "\n")
		if err != nil {
			panic(err)
		}
	}
	defer f.Close()
}
