package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"tee-poc/common"

	"github.com/golang-jwt/jwt/v4"
)

// ReEncryptData is a function that re-encrypts data with a pre-created user specific DEK
func reEncryptData(data []byte, user string) error {

	log.Printf("Updated data to be re-encrypted: %s", data)
	// Retrieve user specific DEK from cloud KMS

	encDek, associatedData, err := common.GetEncDek(user)
	if err != nil {
		return fmt.Errorf("error retrieving DEK for user %s", user)
	}

	// Get Kek AEAD primitive
	kekAead, err := common.CreateKekAEAD()
	if err != nil {
		return fmt.Errorf("error creating KEK AEAD primitive: %s", err)
	}

	// Decrypt the encrypted DEK
	dek, err := common.DecryptKeyWithKEK(kekAead, encDek, associatedData)
	if err != nil {
		return fmt.Errorf("error decrypting DEK: %s", err)
	}

	// Create AEAD primitive
	newAeadPrimitive, err := common.CreateAEADPrimitive(dek)
	if err != nil {
		return fmt.Errorf("error creating new AEAD primitive: %s", err)
	}

	// Encrypt data
	encData, err := common.EncryptDataWithAead(data, newAeadPrimitive, associatedData)
	if err != nil {
		return fmt.Errorf("error encrypting data: %s", err)
	}

	log.Printf("rencrypted data: %s", encData)
	return nil
}

// Decrypt the data received. The data is encrypted with a DEK, which is encrypted with a public keyset.
// Also the data and the key are base64 encoded.
func decryptKeyAndData(encKey string, encData string, associatedData []byte) (decData []byte, err error) {

	decData = []byte{}
	// Decrypt DEK with a private keyset
	// Read private keyset from file
	privateKeyset, err := common.ReadKeysetFromJsonFile(common.PrivateKeyJsonFile)
	if err != nil {
		log.Printf("Error reading private keyset: %s", err)
		return decData, err
	}

	// Base64 decode encryptedKey
	encKeyBytes, err := common.Base64Decode(encKey)
	if err != nil {
		log.Printf("Error base64 decoding encryptedKey: %s", err)
		return decData, err
	}

	dek, err := common.DecryptDekWithProvisionedPrivateKey(encKeyBytes, privateKeyset)
	if err != nil {
		log.Printf("Error decrypting DEK with private key: %s", err)
		return decData, err
	}

	// Create AEAD primitive
	newAeadPrimitive, err := common.CreateAEADPrimitive(dek)
	if err != nil {
		log.Printf("Error creating new AEAD primitive: %s", err)
		return decData, err
	}

	// Base64 decode encryptedData
	encDataBytes, err := common.Base64Decode(encData)
	if err != nil {
		log.Printf("Error base64 decoding encryptedData: %s", err)
		return decData, err
	}

	// Decrypt data
	decData, err = common.DecryptDataWithAead(encDataBytes, newAeadPrimitive, associatedData)
	if err != nil {
		log.Printf("Error decrypting data: %s", err)
		return decData, err
	}
	log.Printf("Decrypted data: %s\n", decData)

	return decData, nil
}

// processData is a function that processes data
func processData(data map[string]interface{}, user string) error {
	// Get the encrypted data
	encData, ok := data["enc_data"].(string)
	if !ok {
		return fmt.Errorf("missing enc_data field")
	}
	log.Printf("Encrypted data: %s\n", encData)

	// Get the encrypted key
	encKey, ok := data["enc_key"].(string)
	if !ok {
		return fmt.Errorf("missing enc_key field")
	}
	log.Printf("Encrypted key: %s\n", encKey)

	requestId, ok := data["requestId"].(string)
	if !ok {
		return fmt.Errorf("missing requestId field")
	}
	log.Printf("Request ID: %s\n", requestId)
	decData, err := decryptKeyAndData(encKey, encData, []byte(user))
	if err != nil {
		return fmt.Errorf("error decrypting key and data: %s", err)
	}

	// Update the data
	decData = append(decData, []byte(" processed")...)

	// Re-encrypt the data with pre-created user specific DEK
	reEncryptData(decData, user)

	return nil
}

// ProcessHandler is a handler function that handles the /process endpoint
func ProcessHandler(w http.ResponseWriter, r *http.Request) {
	var user string

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
			user = u.Username
			break
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

	err = processData(data, user)
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

	// Create per-user DEK and store it in a file

	for _, u := range common.Users {
		associatedData := []byte(strconv.Itoa(u.ID))
		err := common.CreateEncDekPerUser(u.Username, associatedData)
		if err != nil {
			log.Fatal("Error creating encrypted DEK for user:", err)
			return
		}
	}

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
