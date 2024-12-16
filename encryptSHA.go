package encryptSHA

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// EncryptSHA256 cria um novo hash no formato SHA256
func EncryptSHA256(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// EncryptSHA384 cria um novo hash no formato SHA384
func EncryptSHA384(data string) string {
	hash := sha512.New384()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// EncryptSHA512 cria um novo hash no formato SHA512
func EncryptSHA512(data string) string {
	hash := sha512.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}
