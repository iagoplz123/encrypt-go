package encryptAES

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
)

// Gera uma chave aleatória de 16 bytes para AES-128
func generateRandomKey() []byte {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("error generating random key:", err)
	}
	return key
}

var key = generateRandomKey()

// Função que encripta um slice de bytes usando AES-GCM
func encryptAES128(data []byte) ([]byte, error) {
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
func decryptAES128(data []byte) ([]byte, error) {
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
func encryptAESCBC(data []byte) ([]byte, error) {
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
func decryptAESCBC(data []byte) ([]byte, error) {
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

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
)

var alg256 = HS256
var alg384 = HS384
var alg512 = HS512

var Secret string

// hs256 gera uma assinatura HMAC SHA-256
func hs256(secret, data []byte) (ret string, err error) {
	hasher := hmac.New(sha256.New, secret)
	_, err = hasher.Write(data)
	if err != nil {
		return "", err
	}
	r := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r), nil
}

// hs384 gera uma assinatura HMAC SHA-384
func hs384(secret, data []byte) (ret string, err error) {
	hasher := hmac.New(sha512.New384, secret)
	_, err = hasher.Write(data)
	if err != nil {
		return "", err
	}
	r := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r), nil
}

// hs512 gera uma assinatura HMAC SHA-512
func hs512(secret, data []byte) (ret string, err error) {
	hasher := hmac.New(sha512.New, secret)
	_, err = hasher.Write(data)
	if err != nil {
		return "", err
	}
	r := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r), nil
}

// Sign256 cria um token JWT a partir do payload, usando HS256
func SignHS256(payload interface{}) (ret string, err error) {
	if Secret == "" {
		return "", errors.New("secret key is not defined")
	}

	h := header{
		Alg: alg256,
		Typ: "JWT",
	}
	marshal, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	bh := base64.RawURLEncoding.EncodeToString(marshal)

	marshal, err = json.Marshal(payload)
	if err != nil {
		return "", err
	}

	bp := base64.RawURLEncoding.EncodeToString(marshal)

	s := fmt.Sprintf("%s.%s", bh, bp)

	ret, err = hs256([]byte(Secret), []byte(s))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", bh, bp, ret), nil
}

// SignHS384 cria um token JWT a partir do payload, usando HS384
func SignHS384(payload interface{}) (ret string, err error) {
	if Secret == "" {
		return "", errors.New("secret key is not defined")
	}

	h := header{
		Alg: alg384,
		Typ: "JWT",
	}
	marshal, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	bh := base64.RawURLEncoding.EncodeToString(marshal)

	marshal, err = json.Marshal(payload)
	if err != nil {
		return "", err
	}

	bp := base64.RawURLEncoding.EncodeToString(marshal)

	s := fmt.Sprintf("%s.%s", bh, bp)

	ret, err = hs384([]byte(Secret), []byte(s))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", bh, bp, ret), nil
}

// SignHS512 cria um token JWT a partir do payload, usando HS512
func SignHS512(payload interface{}) (ret string, err error) {
	if Secret == "" {
		return "", errors.New("secret key is not defined")
	}

	h := header{
		Alg: alg512,
		Typ: "JWT",
	}
	marshal, err := json.Marshal(h)
	if err != nil {
		return "", err
	}

	bh := base64.RawURLEncoding.EncodeToString(marshal)

	marshal, err = json.Marshal(payload)
	if err != nil {
		return "", err
	}

	bp := base64.RawURLEncoding.EncodeToString(marshal)

	s := fmt.Sprintf("%s.%s", bh, bp)

	ret, err = hs512([]byte(Secret), []byte(s))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s.%s", bh, bp, ret), nil
}

// A função verifyHS256 verifica se o token jwt é valido olhando sua assinatura
func VerifyHS256(token string) (err error) {
	if Secret == "" {
		return errors.New("secret key is not defined")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token format is invalid")
	}

	data := strings.Join(parts[0:2], ".")
	hasher := hmac.New(sha256.New, []byte(Secret))
	_, err = hasher.Write([]byte(data))
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	if hmac.Equal(sig, hasher.Sum(nil)) {
		return nil
	}
	return errors.New("token verification failed")
}

// A função verifyHS384 verifica se o token jwt é valido olhando sua assinatura
func verifyHS384(token string) (err error) {
	if Secret == "" {
		return errors.New("secret key is not defined")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token format is invalid")
	}

	data := strings.Join(parts[0:2], ".")
	hasher := hmac.New(sha512.New384, []byte(Secret))
	_, err = hasher.Write([]byte(data))
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	if hmac.Equal(sig, hasher.Sum(nil)) {
		return nil
	}
	return errors.New("token verification failed")
}

// A função verifyHS256 verifica se o token jwt é valido olhando sua assinatura
func verifyHS512(token string) (err error) {
	if Secret == "" {
		return errors.New("secret key is not defined")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("token format is invalid")
	}

	data := strings.Join(parts[0:2], ".")
	hasher := hmac.New(sha512.New, []byte(Secret))
	_, err = hasher.Write([]byte(data))
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	if hmac.Equal(sig, hasher.Sum(nil)) {
		return nil
	}
	return errors.New("token verification failed")
}
