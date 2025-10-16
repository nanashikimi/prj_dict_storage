package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/edgelesssys/ego/ecrypto"
	"github.com/edgelesssys/estore"
)

//	Plans:
// 1) CLI-Interface(+)
// 2) Persisted Encryption key(+)
// 3) API or REST-Wrapping
// 4) Kubernetes

func getOrCreateKey(path string) []byte {
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

	if err := os.WriteFile("/mnt/key.bin", sealedVal, 0600); err != nil { //rw owner-only
		log.Fatalf("failed to save sealed key: %v", err)
	}

	fmt.Println("🗝🗝🗝  New encryption key created and sealed.")
	return key
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  ego run sec_storage put <key> <value>")
		fmt.Println("  ego run sec_storage get <key>")
		os.Exit(1)
	}

	cmnd := os.Args[1]
	encKey := getOrCreateKey("/mnt/key.bin")
	opts := &estore.Options{EncryptionKey: encKey}
	storage, err := estore.Open("/mnt/users", opts)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	defer storage.Close() // close opened in ending

	switch cmnd {
	case "put":
		if len(os.Args) < 4 { //check input length in arguments
			log.Fatal("Usage: ego run sec_storage put <key> <value>")
		}
		key := []byte(os.Args[2])
		val := []byte(os.Args[3])
		sealedVal, err := ecrypto.SealWithUniqueKey(val, nil) //one-time sealing
		if err != nil {
			log.Fatalf("failed to seal value: %v", err)
		}
		if err := storage.Set(key, sealedVal, nil); err != nil {
			log.Fatalf("failed to store value: %v", err)
		}
		fmt.Println("👉👉👉 Value stored securely ")

	case "get":
		if len(os.Args) < 3 { //check input length in arguments
			log.Fatal("Usage: ego run sec_storage get <key>")
		}
		key := []byte(os.Args[2])
		retVal, closerVal, err := storage.Get(key)
		if err != nil {
			log.Fatalf("failed to read value: %v", err)
		}
		defer closerVal.Close() //close descriptor in ending

		unsealedVal, err := ecrypto.Unseal(retVal, nil)
		if err != nil {
			log.Fatalf("failed to unseal value: %v", err)
		}
		fmt.Println("🔓🔓🔓 Decrypted value:", string(unsealedVal))

	default:
		log.Fatalf("unknown command: %s", cmnd)
	}
}
