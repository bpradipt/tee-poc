package common

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ID       int    `json:"id"`
}

type Message struct {
	Status string `json:"status"`
	Info   string `json:"info"`
}

var Users = []User{
	{
		Username: "user1",
		Password: "password1",
		ID:       1,
	},
	{
		Username: "user2",
		Password: "password2",
		ID:       2,
	},
}

// Secret key for signing JWT tokens
var SecretKey = []byte("secret")

// Public key for encrypting user ephemeral DEK
var PublicKeyJsonFile = "public_keyset.json"

// Private key for decrypting user ephemeral DEK
var PrivateKeyJsonFile = "private_keyset.json"

// Local file to store encrypted per-user DEK
var LocalKeyStoreJsonFile = "local_keystore.json"
