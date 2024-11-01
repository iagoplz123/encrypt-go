package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	cipherText := criptografar256([]byte("iago josé"))
	fmt.Println(cipherText)
}
func criptografar256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	bs := hash.Sum(nil)
	return bs

}
