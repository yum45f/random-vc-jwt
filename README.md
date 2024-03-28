# Random VC-JWT generator

Reference: [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/)  
Reference version: [08 March 2024](https://www.w3.org/TR/2024/WD-vc-jose-cose-20240308/)

## Prerequisites
- Go 1.22.0

## Usage
```bash
go run main.go <number of VCs> <issuer did> <subject did>
```

Output:
 - `tmp/jwt.txt`: line separated VC-JWTs
 - `tmp/jwk/*.json`: JWKs of issuer's genereated keys