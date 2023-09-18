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

1. Client authenticates with API server (POST /login)
2. API server returns JWT token with userid and other claims
3. Client encrypts data with DEK, encrypts the DEK with KEK
4. Client posts data to the API server for processing, including the jwt in the auth header. The data includes enckey, encdata (POST /process)
5. API server verifies the jwt claims 
6. API server sends (userid, enckey, encdata, request_metadata) to process server running inside TEE. It also includes the jwt token, effectively using the jwt token for service-to-service communication.
7. TEE server starts the attestation process using the userid 
8. On successful attestation gets the KEK key for the specific userid, decrypts the DEK and using the DEK and decrypts the data for processing

The TEE flow is TBD