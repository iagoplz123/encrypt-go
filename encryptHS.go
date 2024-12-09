package encryptHS

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

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
func Hs256(secret, data []byte) (ret string, err error) {
	hasher := hmac.New(sha256.New, secret)
	_, err = hasher.Write(data)
	if err != nil {
		return "", err
	}
	r := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r), nil
}

// hs384 gera uma assinatura HMAC SHA-384
func Hs384(secret, data []byte) (ret string, err error) {
	hasher := hmac.New(sha512.New384, secret)
	_, err = hasher.Write(data)
	if err != nil {
		return "", err
	}
	r := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r), nil
}

// hs512 gera uma assinatura HMAC SHA-512
func Hs512(secret, data []byte) (ret string, err error) {
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

	ret, err = Hs256([]byte(Secret), []byte(s))
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

	ret, err = Hs384([]byte(Secret), []byte(s))
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

	ret, err = Hs512([]byte(Secret), []byte(s))
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
func VerifyHS384(token string) (err error) {
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
func VerifyHS512(token string) (err error) {
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
