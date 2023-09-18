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

// SSL certificate and key for HTTPS server
var CertFile = "/path/to/cert.pem"
var KeyFile = "/path/to/key.pem"
