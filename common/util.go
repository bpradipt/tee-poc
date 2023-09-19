package common

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/tink-crypto/tink-go/testing/fakekms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func CreateAEADPrimitive(kh *keyset.Handle) (tink.AEAD, error) {

	// Get the AEAD primitive from the keyset handle
	return aead.New(kh)
}

func CreateDekWithAead() (kh *keyset.Handle, err error) {
	// Create a new AES-GCM keyset handle
	kh, err = keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, err
	}

	return kh, nil
}

func EncryptDataWithAead(data []byte, aeadPrimitive tink.AEAD, associatedData []byte) ([]byte, error) {

	// Encrypt the data
	return aeadPrimitive.Encrypt(data, associatedData)
}

func DecryptDataWithAead(ciphertext []byte, aeadPrimitive tink.AEAD, associatedData []byte) ([]byte, error) {
	// Decrypt the data
	return aeadPrimitive.Decrypt(ciphertext, associatedData)
}

// Add method to encrypt DEK with a public keyset
// The public keyset is created using Tink and provided in advance to the client

func EncryptDekWithProvisionedPublicKey(dek *keyset.Handle, publicJSONKeyset []byte) (encDek []byte, err error) {

	// Initialise encDek to empty slice
	encDek = []byte{}

	// Create a keyset handle from the keyset containing the public key. Because the
	// public keyset does not contain any secrets, we can use [keyset.ReadWithNoSecrets].
	publicKeysetHandle, err := keyset.ReadWithNoSecrets(
		keyset.NewJSONReader(bytes.NewReader(publicJSONKeyset)))
	if err != nil {
		log.Printf("error in reading public keyset: %s", err)
		return encDek, err

	}

	// Retrieve the HybridEncrypt primitive from publicKeysetHandle.
	encPrimitive, err := hybrid.NewHybridEncrypt(publicKeysetHandle)
	if err != nil {
		log.Printf("Error creating AEAD primitive: %s", err)
		return encDek, err
	}

	// Convert dek to bytes
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	insecurecleartextkeyset.Write(dek, writer)
	if err != nil {
		log.Printf("Error converting dek to bytes: %s", err)
		return encDek, err
	}

	encDek, err = encPrimitive.Encrypt(buf.Bytes(), []byte("user-key"))
	if err != nil {
		log.Printf("Error encrypting dek: %s", err)
		return encDek, err
	}

	return encDek, nil
}

// Decrypt DEK with a private keyset
func DecryptDekWithProvisionedPrivateKey(encDek []byte, privateJSONKeyset []byte) (dek *keyset.Handle, err error) {

	/* This fails to import. "importing unencrypted secret key material is forbidden"
	// Create a keyset handle from the keyset containing the private key.
	privateKeysetHandle, err := keyset.ReadWithNoSecrets(
		keyset.NewJSONReader(bytes.NewReader(privateJSONKeyset)))
	if err != nil {
		log.Printf("error in reading private keyset: %s", err)
		return nil, err

	}
	*/

	// Convert privateJSONKeyset bytes to keyset.Handle
	privateKeysetHandle, err := insecurecleartextkeyset.Read(
		keyset.NewJSONReader(bytes.NewBuffer(privateJSONKeyset)))

	if err != nil {
		log.Printf("error in reading private keyset: %s", err)
		return nil, err
	}

	// Retrieve the HybridEncrypt primitive from publicKeysetHandle.
	encPrimitive, err := hybrid.NewHybridDecrypt(privateKeysetHandle)
	if err != nil {
		log.Printf("Error creating AEAD primitive: %s", err)
		return dek, err
	}

	dekBytes, err := encPrimitive.Decrypt(encDek, []byte("user-key"))
	if err != nil {
		log.Printf("Error decrypting dek: %s", err)
		return nil, err
	}

	// Convert dekBytes to keyset.Handle
	buf := bytes.NewReader(dekBytes)
	reader := keyset.NewBinaryReader(buf)
	dek, err = insecurecleartextkeyset.Read(reader)
	if err != nil {
		log.Printf("Error converting dekBytes to keyset.Handle: %s", err)
		return nil, err
	}

	return dek, nil

}

// Read keyset json file and return bytes
func ReadKeysetFromJsonFile(filename string) ([]byte, error) {
	// Read the keyset json file
	jsonFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	// Read the json file as bytes
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	return byteValue, nil
}

// The fake KMS should only be used in tests. It is not secure.
const keyURI = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE"

func CreateKekAEAD() (kekAEAD tink.AEAD, err error) {
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
// The KEK should be created using cloud KMS

func EncryptKeyWithKEK(kekAEAD tink.AEAD, kh *keyset.Handle, keysetAssociatedData []byte) ([]byte, error) {

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

func DecryptKeyWithKEK(kekAEAD tink.AEAD, encryptedKeyset []byte, keysetAssociatedData []byte) (*keyset.Handle, error) {

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

// GenerateToken is a function that generates a JWT token with the user id as a claim
func GenerateToken(userid int) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userid": userid,
	})
	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// VerifyToken is a function that verifies a JWT token and returns the user id claim
func VerifyToken(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return SecretKey, nil
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

// Base64 decode string
func Base64Decode(b64Str string) ([]byte, error) {

	decodedBytes, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return nil, err
	}

	return decodedBytes, nil
}

// Base64 encode string
func Base64Encode(str string) (string, error) {

	encodedStr := base64.StdEncoding.EncodeToString([]byte(str))

	return encodedStr, nil
}
