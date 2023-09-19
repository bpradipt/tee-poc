package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"tee-poc/common"

	"github.com/google/uuid"
)

// LoginHandler is a handler function that handles the /login endpoint
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user common.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, u := range common.Users {
		if u.Username == user.Username && u.Password == user.Password {
			token, err := common.GenerateToken(u.ID)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			log.Printf("User %s logged in successfully\n", user.Username)
			json.NewEncoder(w).Encode(common.Message{Status: "success", Info: token})
			return
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(common.Message{Status: "fail", Info: "invalid username or password"})
}

// SendData is a function that sends data to the process server
func SendData(data map[string]interface{}, token string) error {
	// Send data to process server listening on port 8081
	// ...
	// Send HTTP post request to process server
	// ...

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling data: %s", err)
		return err
	}

	client := &http.Client{}
	// Create HTTP request to process server listening on port 8081

	req, err := http.NewRequest("POST", "http://localhost:8081/process", bytes.NewBuffer(jsonData))
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

// ProcessHandler is a handler function that handles the /process endpoint
func ProcessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(common.Message{Status: "fail", Info: "missing authorization header"})
		return
	}
	userid, err := common.VerifyToken(tokenString)
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

	// Create a requestId (uid) to be added to the data
	requestId, err := uuid.NewRandom()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		// Send error message to client
		json.NewEncoder(w).Encode(common.Message{Status: "failed to generate request Id", Info: err.Error()})
		return
	}

	b64RequestID, err := common.Base64Encode(requestId.String())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		// Send error message to client
		json.NewEncoder(w).Encode(common.Message{Status: "failed to encode request Id", Info: err.Error()})
		return
	}

	data["requestId"] = b64RequestID

	// Send data to process server listening on port 8081
	err = SendData(data, tokenString)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		// Send error message to client
		json.NewEncoder(w).Encode(common.Message{Status: "failed to send data", Info: err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(common.Message{Status: "success", Info: "data processed successfully"})
}

func main() {
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/process", ProcessHandler)

	// Start HTTPS server
	//err := http.ListenAndServeTLS(":8080", common.CertFile, common.KeyFile, nil)
	//if err != nil {
	//	log.Println("There was an error listening on port :8080", err)
	//}

	// Start HTTP server
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Println("There was an error listening on port :8080", err)
	}

}
