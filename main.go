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
// 3) API or REST-Wrapping(+) (DELETE and GET in future)
// 4) Kubernetes(+)
// 5) MarbleRun for Kubernetes

func getOrCreateKey(path string) []byte {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("failed to create directory %s: %v", dir, err)
	}

	if data, err := os.ReadFile(path); err == nil { // file by path exists ==>
		key, err := ecrypto.Unseal(data, nil) // ==> decrypt
		if err != nil {
			log.Fatalf("failed to unseal existing key: %v", err)
		}
		return key
	}
	//not exists ==>
	key := make([]byte, 32) //==> create new one for 256-bit
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	sealedVal, err := ecrypto.SealWithProductKey(key, nil) //key for device
	if err != nil {
		log.Fatalf("failed to seal key: %v", err)
	}

	if err := os.WriteFile(path, sealedVal, 0600); err != nil { //rw owner-only
		log.Fatalf("failed to save sealed key: %v", err)
	}

	fmt.Println("🗝🗝🗝  New encryption key created and sealed.")
	return key
}

// REST API Handler
type KVRequest struct {
	Key   string `json:"key"`
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

	http.HandleFunc("/put", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req KVRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}

		sealedVal, err := ecrypto.SealWithUniqueKey([]byte(req.Value), nil)
		if err != nil {
			http.Error(w, "failed to seal", http.StatusInternalServerError)
			return
		}

		if err := storage.Set([]byte(req.Key), sealedVal, nil); err != nil {
			http.Error(w, "failed to store", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "👉👉👉 Stored key=%s securely\n", req.Key)
	})

	http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "use GET", http.StatusMethodNotAllowed)
			return
		}

		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "missing key param", http.StatusBadRequest)
			return
		}

		data, closer, err := storage.Get([]byte(key))
		if err != nil {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		defer closer.Close()

		unsealed, err := ecrypto.Unseal(data, nil)
		if err != nil {
			http.Error(w, "failed to unseal", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "🔓🔓🔓 Value: %s\n", unsealed)
	})

	fmt.Println("🚀🚀🚀 Secure Key-Value REST API running on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
