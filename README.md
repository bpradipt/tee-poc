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
When running the client you will hit the following issue 
https://protobuf.dev/reference/go/faq/#namespace-conflict

Run the client using the following option
```
GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn ./client
```
# Flow

## Prerequisites

1. Create an assymetric key set with tinkey
   ```
    tinkey create-keyset --key-template ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM --out keyset.json
    tinkey create-public-keyset --in keyset.json --out pubkey.json
    ```
2. Encrypt the private part of the key using KEK from Cloud KMS and save it
3. Generate per-user DEK in Cloud KMS
4. Have a mapping of userid to DEK id to enable key retrieval from Cloud KMS
   
## Implementation

1. Client authenticates with API server (POST /login)
2. API server returns JWT token with userid and other claims
3. Client encrypts data with locally generated DEK
4. Client encrypts the DEK with a pre-created public key (KEK)
5.  Client posts data to the API server for processing, including the jwt in the auth header. The data includes enckey, encdata (POST /process)
6.  API server verifies the jwt claims 
7.  API server sends (userid, enckey, encdata, request_metadata) to process server running inside TEE. It also includes the jwt token, effectively using the jwt token for service-to-service communication.
8. Process server gets the private key from cloud KMS to decrypt the user provided data
9. Perform processing on the data
10. Encrypt the output with per-user DEK and add associated data as userid+request_metadata
11. Store the output in DB

The TEE flow is TBD