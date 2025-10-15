package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/estore"
)

func main() {
	//	Plans:
	// 1) CLI-Interface
	// 2) Persisted Encryption key
	// 3) API or REST-Wrapping
	// 4) Kubernetes
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		log.Fatalf("failed to generate encryption key: %v", err)
	}

	opts := &estore.Options{
		EncryptionKey: encryptionKey,
	}

	store, err := estore.Open("users", opts)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	key := []byte("username")
	value := []byte("alex")

	sealed, err := ecrypto.SealWithUniqueKey(value, nil)
	if err != nil {
		log.Fatalf("failed to seal value: %v", err)
	}

	if err := store.Set(key, sealed, nil); err != nil {
		log.Fatalf("failed to store value: %v", err)
	}
	fmt.Println("✅ Encrypted value saved!")

	retrieved, closer, err := store.Get(key)
	if err != nil {
		log.Fatalf("failed to read value: %v", err)
	}
	defer closer.Close()

	unsealed, err := ecrypto.Unseal(retrieved, nil)
	if err != nil {
		log.Fatalf("failed to unseal value: %v", err)
	}

	fmt.Println("🔓 Decrypted value:", string(unsealed))
}
