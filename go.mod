module tee-poc

go 1.20

require (
	github.com/bpradipt/tee-poc v0.0.0-00010101000000-000000000000
	github.com/golang-jwt/jwt/v4 v4.5.0
	github.com/tink-crypto/tink-go v0.0.0-20230613075026-d6de17e3f164
	github.com/tink-crypto/tink-go/v2 v2.0.0
)

require (
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)

replace github.com/bpradipt/tee-poc => ./
