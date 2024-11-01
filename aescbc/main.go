package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

var key = []byte(generateRandomKey())

func encryptAES256(data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("tamanho de chave errado %\n", err)
	}

	dataWithPadding := PKCS7Padding(data)
	buffer := make([]byte, aes.BlockSize+len(dataWithPadding))

	iv := buffer[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println(err)
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(buffer[len(iv):], dataWithPadding)

	return buffer
}

func decryptAES256(data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println("tamanho de chave errado %\n", err)
	}

	iv := data[0:aes.BlockSize]

	buffer := make([]byte, len(data)-len(iv))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(buffer, data[len(iv):])

	return PKCS7Unpadding(buffer)
}

func PKCS7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7Unpadding(plantText []byte) []byte {
	length := len(plantText)
	padding := int(plantText[length-1])
	return plantText[:(length - padding)]
}

func generateRandomKey() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Println("Erro ao criar chave%\n", err)
	}
	return hex.EncodeToString(bytes)
}
func main() {

	encryptedText := encryptAES256([]byte("flamengo maior time do mundo"))
	fmt.Println(string(encryptedText))
	decrypetedText := decryptAES256(encryptedText)
	fmt.Println(string(decrypetedText))

}
