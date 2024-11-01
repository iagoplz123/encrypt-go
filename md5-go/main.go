package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

func main() {
	cipherText := criptografar([]byte("megadeth"), "dave")
	fmt.Println(string(cipherText))
	plainText := descriptografar(cipherText, "dave")
	fmt.Println(string(plainText))

}

func criarHash(chave string) string {
	hasher := md5.New()
	hasher.Write([]byte(chave))
	return hex.EncodeToString(hasher.Sum(nil))
}
func criptografar(data []byte, s string) []byte {
	block, _ := aes.NewCipher([]byte(criarHash(s)))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return cipherText
}
func descriptografar(data []byte, s string) []byte {
	chave := []byte(criarHash(s))
	block, err := aes.NewCipher(chave)
	if err != nil {
		log.Println(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
	}
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Println(err)
	}
	return plaintext
}
