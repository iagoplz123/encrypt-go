package main

import (
	"fmt"

	encryptSHA "github.com/iagoplz123/encrypt-go/SHA-go"
)

func main() {
	cipherText := encryptSHA.EncryptSHA256("12345678")
	fmt.Println(cipherText)

	cipherText = encryptSHA.EncryptSHA384("12345678")
	fmt.Println(cipherText)

	cipherText = encryptSHA.EncryptSHA512("12345678")
	fmt.Println(cipherText)
}
