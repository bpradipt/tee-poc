package common

import (
	"encoding/json"
	"os"
)

// Add method to create DEK using CreateDekWithAead, encrypt it EncryptKeyWithKEK and store the encrypted
// DEK in a file along with userid and associated data
// The encrypted DEK is stored in a file along with the userid and associated data

func CreateEncDekPerUser(user string, associatedData []byte) (err error) {

	// Create DEK
	dek, err := CreateDekWithAead()
	if err != nil {
		return err
	}

	// Create KEK  primitive
	kekAead, err := CreateKekAEAD()
	if err != nil {
		return err
	}

	// Encrypt DEK with KEK
	encDek, err := EncryptKeyWithKEK(kekAead, dek, associatedData)
	if err != nil {
		return err
	}

	// Store the encrypted DEK in a file along with the user and associated data
	err = StoreEncDek(encDek, user, associatedData)
	if err != nil {
		return err
	}

	return nil
}

// Add method to store the encrypted DEK in a file along with the user and associated data
// Use Json encoding to store the encrypted DEK, user and associated data in a file

func StoreEncDek(encDek []byte, user string, associatedData []byte) (err error) {

	// Create a map to store the encrypted DEK, user and associated data
	encDekMap := make(map[string][]byte)

	// Store the encrypted DEK, user and associated data in the map
	encDekMap["encDek"] = encDek
	encDekMap["user"] = []byte(user)
	encDekMap["associatedData"] = associatedData

	// Open the file LocalKeyStoreJsonFile
	file, err := os.OpenFile(LocalKeyStoreJsonFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encode the map
	enc := json.NewEncoder(file)
	err = enc.Encode(encDekMap)
	if err != nil {
		return err
	}

	return nil
}

// Get the encrypted DEK and associated data from the file LocalKeyStoreJsonFile for the user

func GetEncDek(user string) (encDek []byte, associatedData []byte, err error) {

	encDek = []byte{}
	associatedData = []byte{}

	// Open the file LocalKeyStoreJsonFile
	file, err := os.Open(LocalKeyStoreJsonFile)
	if err != nil {
		return encDek, associatedData, err
	}
	defer file.Close()

	// Decode the file
	dec := json.NewDecoder(file)
	for dec.More() {
		// Read the next line
		var encDekMap map[string][]byte
		err := dec.Decode(&encDekMap)
		if err != nil {
			return encDek, associatedData, err
		}

		// Check if the user matches
		if string(encDekMap["user"]) == user {
			encDek = encDekMap["encDek"]
			associatedData = encDekMap["associatedData"]
			return encDek, associatedData, nil
		}
	}

	return encDek, associatedData, nil
}
