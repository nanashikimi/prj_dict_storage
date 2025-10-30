package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/estore"
)

//	Plans:
// 1) CLI-Interface(+)
// 2) Persisted Encryption key(+)
// 3) API or REST-Wrapping(+) (DELETE and LIST in future)
// 4) Kubernetes(+)
// 5) MarbleRun for Kubernetes

func getOrCreateKey(path string) []byte {
	dir := filepath.Dir(path)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatalf("failed to create directory %s: %v", dir, err)
	}

	data, err := os.ReadFile(path)
	if err == nil { // file by path exists ==>
		key, err := ecrypto.Unseal(data, nil) // ==> decrypt
		if err != nil {
			log.Fatalf("failed to unseal existing key: %v", err)
		}
		return key
	}
	//not exists ==>
	key := make([]byte, 32) //==> create new one for 256-bit
	_, err = rand.Read(key)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	sealedVal, err := ecrypto.SealWithProductKey(key, nil) //key for device
	if err != nil {
		log.Fatalf("failed to seal key: %v", err)
	}

	err = os.WriteFile(path, sealedVal, 0600)
	if err != nil {
		log.Fatalf("failed to save sealed key: %v", err)
	} //rw owner-only
	fmt.Println("🗝🗝🗝  New encryption key created and sealed.")
	return key
}

// REST API Handler
type KeyValRequest struct {
	Key   string `json:"key"` //K(upper) for Go typisation, k(lower) as keyword for json
	Value string `json:"value"`
}

func main() {
	encKey := getOrCreateKey("key.bin")
	opts := &estore.Options{EncryptionKey: encKey}
	storage, err := estore.Open("users", opts)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	defer storage.Close() // close opened in ending

	http.HandleFunc("/put", func(w http.ResponseWriter, r *http.Request) { // POST handler
		if r.Method != http.MethodPost {                                   // != "POST"
			http.Error(w, "use POST", http.StatusMethodNotAllowed) // only method POST allowed, cause we need to create data
			return
		}

		body, err := io.ReadAll(r.Body) //read json bytewise with failure check
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close() //free resources(like in C)

		var req KeyValRequest
		err = json.Unmarshal(body, &req)
		if err != nil { // parsing + failure check
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}

		sealedVal, err := ecrypto.SealWithUniqueKey([]byte(req.Value), nil) // only this device and only this session
		if err != nil {
			http.Error(w, "failed to seal", http.StatusInternalServerError)
			return
		}
		err = storage.Set([]byte(req.Key), sealedVal, nil)
		if err != nil {
			http.Error(w, "failed to store", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "👉👉👉 Stored key=%s securely 👈👈👈\n", req.Key)
	})

	http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet { //!= "GET"
			http.Error(w, "use GET", http.StatusMethodNotAllowed)
			return
		}

		key := r.URL.Query().Get("key") //get value by param key
		if key == "" {                  //key not delivered
			http.Error(w, "missing key param", http.StatusBadRequest)
			return
		}
		data, closer, err := storage.Get([]byte(key)) //getting data
		if err != nil {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		defer closer.Close() //free

		unsealed, err := ecrypto.Unseal(data, nil) //unsealing + failure check
		if err != nil {
			http.Error(w, "failed to unseal", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json") //set response header as JSON
		fmt.Fprintf(w, "🔓🔓🔓 Value: %s\n", unsealed)        // HERE WOULD BE LOGICAL TO RETURN REAL JSON
	})

	fmt.Println("🔥🎖️🚀 Secure Key-Value REST API running on :8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("server error: %v", err)
	}
}
