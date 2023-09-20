# Install tinkey tool

```
brew tap tink-crypto/tink-tinkey https://github.com/tink-crypto/tink-tinkey

brew install tinkey
```

# Running the programs

Build the individual programs

```
pusd client
go build -o client *.go
popd

pushd api_server
go build -o api_server *.go
popd

pushd process_server
go build -o process_server *.go
popd

```

Run the api_server and process_server in separate terminals.
Run the client program to see the flow from the api_server to the process_server

# Issues

## Protobuf namespace conflict
When running the programs you will hit the following issue 
https://protobuf.dev/reference/go/faq/#namespace-conflict

Run the `process_server` using the following option
```
GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn ./process_server
```

Run the `api_server` using the following option
```
GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn ./api_server
```

Run the `client` using the following option
```
GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn ./client
```

# Flow

## Prerequisites

1. Create an asymmetric key set with tinkey
   ```
    tinkey create-keyset --key-template ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM --out private_keyset.json
    tinkey create-public-keyset --in private_keyset.json --out public_keyset.json
    ```
2. Copy the `private_keyset.json` under `process_server` and `public_keyset.json` under `client` folder. Note that you should not do this for real systems. Always encrypt the private part of the key using KEK from a KMS before saving it.
   
## Implementation

1. Client authenticates with API server (POST /login)
2. API server returns JWT token with userid and other claims
3. Client encrypts data with locally generated ephemeral DEK
4. Client encrypts the DEK with a pre-created public key (`public_keyset.json`). 
5. Client posts data to the API server for processing, including the jwt in the auth header. The data includes enckey, encdata (POST /process)
6. API server verifies the jwt claims
7. API server sends (userid, enckey, encdata, requestId) to process server running inside TEE. It also includes the jwt token, effectively using the jwt token for service-to-service communication.
8. Process server uses the private key (`private_keyset.json`) to decrypt the `enckey` and uses this key to decrypt `encdata`
9. Process server updates the plaintext data and re-encrypts it with a user-specific encryption key. The per-user encryption keys is created during start of the process server.