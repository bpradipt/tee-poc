package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"log"
	"net/http"

	"tee-poc/common"
)

// Login is a function that sends a POST request to the /login endpoint with a username and password, and returns the JWT token if successful
func Login(username, password string) (string, error) {
	user := common.User{Username: username, Password: password}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return "", err
	}
	resp, err := http.Post("http://localhost:8080/login", "application/json", bytes.NewBuffer(userJSON))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var message common.Message
	err = json.Unmarshal(body, &message)
	if err != nil {
		return "", err
	}
	if message.Status == "success" {
		return message.Info, nil
	}
	return "", fmt.Errorf(message.Info)
}

// Send encrypted data to /process endpoint of HTTP server
func Process(token string, encData []byte, encKey []byte) error {
	client := &http.Client{}
	data := map[string]interface{}{
		"enc_data": base64.StdEncoding.EncodeToString(encData),
		"enc_key":  base64.StdEncoding.EncodeToString(encKey),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling data: %s", err)
		return err
	}
	req, err := http.NewRequest("POST", "http://localhost:8080/process", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error creating request:", err)
		return err
	}
	// Add token to the Authorization header
	req.Header.Add("Authorization", token)

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error sending data:", err)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response:", err)
		return err
	}
	var message common.Message
	err = json.Unmarshal(body, &message)
	if err != nil {
		log.Println("Error unmarshalling response:", err)
		return err
	}
	if message.Status == "success" {
		return nil
	}
	log.Println("Error processing data:", message.Info)
	return fmt.Errorf(message.Info)
}

func main() {

	// Create DEK
	dek, err := common.CreateDekWithAead()
	if err != nil {
		log.Fatal("Error creating data encryption key:", err)
		return
	}

	// Create AEAD primitive
	aeadPrimitive, err := common.CreateAEADPrimitive(dek)
	if err != nil {
		log.Fatal("Error creating AEAD primitive:", err)
		return
	}

	// Encrypt data
	inputData := []byte("Sensitive information")
	associatedData := []byte(common.Users[0].Username)
	encData, err := common.EncryptDataWithAead(inputData, aeadPrimitive, associatedData)
	if err != nil {
		log.Fatal("Error encrypting data:", err)
		return
	}

	log.Printf("Input data: %s\n", inputData)

	// Encrypt DEK with a public keyset
	// Read public keyset from file
	publicKeyset, err := common.ReadKeysetFromJsonFile(common.PublicKeyJsonFile)
	if err != nil {
		log.Fatal("Error reading public keyset:", err)
		return
	}

	encKey, err := common.EncryptDekWithProvisionedPublicKey(dek, publicKeyset)
	if err != nil {
		log.Fatal("Error encrypting DEK with public key:", err)
		return
	}

	// Login to server and get jwt token
	token, err := Login(common.Users[0].Username, common.Users[0].Password)
	if err != nil {
		log.Println("Login failed:", err)
		return
	}
	log.Println("Login successful:", token)

	// Send the encrypted data to the server for processing
	err = Process(token, encData, encKey)
	if err != nil {
		log.Println("Error processing data:", err)
		return
	}

	fmt.Println("Data sent successfully")

}
