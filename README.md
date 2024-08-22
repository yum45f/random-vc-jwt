# Random VC-JWT generator

Reference: [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/)  
Reference version: [13 August 2024](https://www.w3.org/TR/2024/CRD-vc-jose-cose-20240813/)

## Prerequisites
- Go 1.22.0

## Usage
```bash
go run main.go --alg <dsa alg.> <number of VCs> <issuer URI> <subject URI> 
```

Output:
 - `tmp/vc-jwts.txt`: line separated VC-JWTs
 - `tmp/jwk/*.json`: JWKs of issuer's genereated keys

### Example
```bash
go run main.go --alg p256 10 http://example.com/issuer http://example.com/subject
```