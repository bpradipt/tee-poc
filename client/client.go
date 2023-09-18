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

	"github.com/tink-crypto/tink-go/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// The fake KMS should only be used in tests. It is not secure.
const keyURI = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"

func createAEADPrimitive(kh *keyset.Handle) (tink.AEAD, error) {

	// Get the AEAD primitive from the keyset handle
	return aead.New(kh)
}

func createDEK() (kh *keyset.Handle, err error) {
	// Create a new AES-GCM keyset handle
	kh, err = keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, err
	}

	return kh, nil
}

func encryptData(data []byte, aeadPrimitive tink.AEAD) ([]byte, error) {
	// Add associated data to the AEAD primitive
	// TBD: use actual associated data, eg auth-id, session-id etc.
	associatedData := []byte("associated data")
	// Encrypt the data
	return aeadPrimitive.Encrypt(data, associatedData)
}

func decryptData(ciphertext []byte, aeadPrimitive tink.AEAD) ([]byte, error) {
	// Add associated data to the AEAD primitive
	// TBD: use actual associated data, eg auth-id, session-id etc.
	associatedData := []byte("associated data")
	// Decrypt the data
	return aeadPrimitive.Decrypt(ciphertext, associatedData)
}

func createKekAEAD() (kekAEAD tink.AEAD, err error) {
	// Get a KEK (key encryption key) AEAD. This is usually a remote AEAD to a KMS. In this example,
	// we use a fake KMS to avoid making RPCs.
	client, err := fakekms.NewClient(keyURI)
	if err != nil {
		log.Printf("error in creating fakeKMS client: %s", err)
		return nil, err
	}
	kekAEAD, err = client.GetAEAD(keyURI)
	if err != nil {
		log.Printf("error in creating KEK AEAD: %s", err)
		return nil, err
	}
	return kekAEAD, nil
}

// Encrypt DEK with KEK

func encryptKeyWithKEK(kekAEAD tink.AEAD, kh *keyset.Handle) ([]byte, error) {

	// Choose some associated data. This is the context in which the keyset will be used.
	keysetAssociatedData := []byte("keyset encryption example")

	// Encrypt the keyset with the KEK AEAD and the associated data.
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err := kh.WriteWithAssociatedData(writer, kekAEAD, keysetAssociatedData)
	if err != nil {
		log.Printf("error in writing keyset: %s", err)
		return nil, err
	}
	encryptedKeyset := buf.Bytes()

	return encryptedKeyset, nil

}

// Decrypt DEK encrypted with KEK

func decryptKeyWithKEK(kekAEAD tink.AEAD, encryptedKeyset []byte) (*keyset.Handle, error) {

	// Choose some associated data. This is the context in which the keyset will be used.
	keysetAssociatedData := []byte("keyset encryption example")

	// To use the primitive, we first need to decrypt the keyset. We use the same
	// KEK AEAD and the same associated data that we used to encrypt it.
	reader := keyset.NewBinaryReader(bytes.NewReader(encryptedKeyset))
	kh, err := keyset.ReadWithAssociatedData(reader, kekAEAD, keysetAssociatedData)
	if err != nil {
		log.Printf("error in getting DEK: %s", err)
		return nil, err
	}

	return kh, nil
}

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

	// Authenticate with server and get jwt token
	// TBD: use actual authentication mechanism

	// Send a post to /login endpoint with username and password for authentication
	// to get a jwt token. The server is HTTPS

	// Create DEK
	dek, err := createDEK()
	if err != nil {
		log.Fatal("Error creating data encryption key:", err)
		return
	}

	// Create AEAD primitive
	aeadPrimitive, err := createAEADPrimitive(dek)
	if err != nil {
		log.Fatal("Error creating AEAD primitive:", err)
		return
	}

	// Encrypt data
	inputData := []byte("Sensitive information")
	encData, err := encryptData(inputData, aeadPrimitive)
	if err != nil {
		log.Fatal("Error encrypting data:", err)
		return
	}

	/*
		// Decrypt data
		decData, err := decryptData(encData, aeadPrimitive)
		if err != nil {
			log.Fatal("Error decrypting data:", err)
			return
		}

		// Check if decrypted data matches original data
		if !bytes.Equal(inputData, decData) {
			log.Fatal("Decrypted data does not match original data")
			return
		}

		fmt.Println("Data encrypted and decrypted successfully")
	*/

	// Create KEK AEAD

	kekAEAD, err := createKekAEAD()
	if err != nil {
		log.Fatal("Error creating KEK AEAD:", err)
		return
	}

	// Encrypt key with KEK
	encKey, err := encryptKeyWithKEK(kekAEAD, dek)
	if err != nil {
		log.Fatal("Error encrypting dek with KEK:", err)
		return
	}

	/*
		// Store the encrypted key in a remote location for retrieval later

		// Store the enckey in a file name kek.enc

		err = os.WriteFile("kek.enc", encKey, 0644)
		if err != nil {
			log.Fatal("Error writing encrypted key to file:", err)
			return
		}
	*/

	// Decrypt key with KEK
	newDek, err := decryptKeyWithKEK(kekAEAD, encKey)
	if err != nil {
		log.Fatal("Error decrypting dek with KEK:", err)
		return
	}
	// Create AEAD primitive
	newAeadPrimitive, err := createAEADPrimitive(newDek)
	if err != nil {
		log.Fatal("Error creating new AEAD primitive:", err)
		return
	}

	// Decrypt data
	newDecData, err := decryptData(encData, newAeadPrimitive)
	if err != nil {
		log.Fatal("Error decrypting data:", err)
		return
	}

	// Check if decrypted data matches original data
	if !bytes.Equal(inputData, newDecData) {
		log.Fatal("Decrypted data does not match original data")
		return
	}

	fmt.Println("Data encrypted and decrypted successfully")

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
