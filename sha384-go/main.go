package main

import (
	"crypto/sha512"
	"fmt"
)

func main() {
	cipherText := criptografar384([]byte("iago josé"))
	fmt.Println(cipherText)
}
func criptografar384(data []byte) []byte {
	hash := sha512.New384()
	hash.Write(data)
	bs := hash.Sum(nil)
	return bs

}
