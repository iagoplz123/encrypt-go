package encrypt_aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
)

// Gera uma chave aleatória de 16 bytes para AES-128
func GenerateRandomKey() []byte {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("error generating random key:", err)
	}
	return key
}

var key = GenerateRandomKey()

// Função que encripta um slice de bytes usando AES-GCM
func EncryptAES128(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating the GCM: %w", err)
	}

	// Cria um nonce de 12 bytes para o GCM
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}

	// Encripta os dados e adiciona a tag de autenticação automaticamente
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Função que desencripta um slice de bytes encriptado usando AES-GCM
func DecryptAES128(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// Desencripta o dado e verifica a tag de autenticação automaticamente
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error when decrypting: %w", err)
	}

	return plaintext, nil
}

// Função que encripta um slice de bytes usando AES-CBC
func EncryptAESCBC(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}

	dataWithPadding := PKCS7Padding(data)
	buffer := make([]byte, aes.BlockSize+len(dataWithPadding))

	// Gerando IV aleatório
	iv := buffer[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("error generating IV: %w", err)
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(buffer[aes.BlockSize:], dataWithPadding)

	return buffer, nil
}

// Função que desencripta um slice de bytes encriptado em AESCBC
func DecryptAESCBC(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}

	// Extrai IV do começo do dado encriptado
	iv := data[:aes.BlockSize]
	encryptedData := data[aes.BlockSize:]

	decrypted := make([]byte, len(encryptedData))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(decrypted, encryptedData)

	return PKCS7Unpadding(decrypted)
}

// Função de padding para alinhamento de bloco
func PKCS7Padding(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Função de unpadding para remover o padding após descriptografar
func PKCS7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	padding := int(data[length-1])

	if padding > length {
		return nil, fmt.Errorf("padding error")
	}
	return data[:length-padding], nil
}
