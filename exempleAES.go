package main

import (
	"encoding/hex"
	"fmt"
	"log"

	encryptAES "github.com/iagoplz123/encrypt-go/AES-go"
)

func main() {
	plaintext := "12345678"
	// Encripta o texto
	encryptedText, err := encryptAES.EncryptAES128([]byte(plaintext))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(encryptedText))

	// Desencripta o texto
	decryptedText, err := encryptAES.DecryptAES128(encryptedText)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(decryptedText))
}
