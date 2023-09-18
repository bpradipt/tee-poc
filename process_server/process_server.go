package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"tee-poc/common"

	"github.com/golang-jwt/jwt/v4"
)

// processData is a function that processes data
func processData(data map[string]interface{}) error {
	// Get the encrypted data
	encryptedData, ok := data["enc_data"].(string)
	if !ok {
		return fmt.Errorf("missing enc_data field")
	}
	log.Printf("Encrypted data: %s\n", encryptedData)

	// Get the encrypted key
	encryptedKey, ok := data["enc_key"].(string)
	if !ok {
		return fmt.Errorf("missing enc_key field")
	}
	log.Printf("Encrypted key: %s\n", encryptedKey)

	return nil
}

// ProcessHandler is a handler function that handles the /process endpoint
func ProcessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(common.Message{Status: "fail", Info: "missing authorization header"})
		return
	}
	userid, err := VerifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(common.Message{Status: "fail", Info: err.Error()})
		return
	}
	log.Printf("User %d has sent request for processing\n", userid)

	// Print the username of the user with ID userid
	for _, u := range common.Users {
		if u.ID == userid {
			log.Printf("Username: %s\n", u.Username)
		}
	}

	// Read the request body
	var data map[string]interface{}
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Do something with the data
	log.Printf("Data received: %v\n", data)

	err = processData(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		// Send error message to client
		json.NewEncoder(w).Encode(common.Message{Status: "fail", Info: err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(common.Message{Status: "success", Info: "data processed successfully"})
}

// VerifyToken is a function that verifies a JWT token and returns the user id claim
func VerifyToken(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return common.SecretKey, nil
	})
	if err != nil {
		return 0, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		log.Printf("Claims: %v\n", claims)
		userid := int(claims["userid"].(float64))
		return userid, nil
	}
	return 0, fmt.Errorf("invalid token")
}

func main() {

	http.HandleFunc("/process", ProcessHandler)

	// Start HTTPS server
	//err := http.ListenAndServeTLS(":8081", common.CertFile, common.KeyFile, nil)
	//if err != nil {
	//	log.Println("There was an error listening on port :8080", err)
	//}

	// Start HTTP server
	err := http.ListenAndServe(":8081", nil)
	if err != nil {
		log.Println("There was an error listening on port :8081", err)
	}

}
