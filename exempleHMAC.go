package main

import (
	"fmt"

	encryptHS "github.com/iagoplz123/encrypt-go/HMAC-go"
)

func main() {
	Secret := "123456" // Na produção, use uma forma mais segura de gerenciar segredos
	// cadastre um token
	token, err := encryptHS.SignHS384(struct {
		Name string `json:"name"`
	}{Name: "langwan"}, Secret)
	if err != nil {
		fmt.Println("error signing token:", err)
		return
	}
	fmt.Println("Generated token:", token)

	// verifica o token
	err = encryptHS.VerifyHS384(token, Secret)
	if err != nil {
		fmt.Println("Token verification failed:", err)
	} else {
		fmt.Println("Token verification succeeded")
	}

}
