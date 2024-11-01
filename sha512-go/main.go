package main

import (
	"crypto/sha512"
	"fmt"
)

func main() {
	cipherText := Encrypt512([]byte("iago josé"))
	fmt.Println(cipherText)
}
func Encrypt512(data []byte) []byte {
	hash := sha512.New()
	hash.Write(data)
	bs := hash.Sum(nil)
	return bs

}
