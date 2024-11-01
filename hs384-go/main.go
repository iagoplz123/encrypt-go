package main

import (
	"crypto/hmac"
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
	HS384 = "HS385"
)

var alg = HS384

var Secret string

func hs384(secret, data []byte) (ret string, err error) {
	hasher := hmac.New(sha512.New384, secret)
	_, err = hasher.Write(data)
	if err != nil {
		return "", err
	}
	r := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(r), nil
}

func Sign(payload interface{}) (ret string, err error) {
	h := header{
		Alg: alg,
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

func Verify(token string) (err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("parts len error")
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
	return errors.New("verify is invalid")
}
func main() {
	Secret = "123456"

	token, _ := Sign(struct {
		Name string `json:"name"`
	}{Name: "langwan"})
	err := Verify(token)
	if err != nil {
		fmt.Println("failed")
	} else {
		fmt.Println("ok")
	}
}
