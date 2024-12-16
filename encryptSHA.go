package encryptSHA

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// encryptSHA256 cria um novo hash no formato SHA256
func encryptSHA256(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// encryptSHA384 cria um novo hash no formato SHA384
func encryptSHA384(data string) string {
	hash := sha512.New384()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// encryptSHA512 cria um novo hash no formato SHA512
func encryptSHA512(data string) string {
	hash := sha512.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}
