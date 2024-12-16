package main

import (
	"fmt"
	"log"
	"time"

	encryptRSA "github.com/iagoplz123/encrypt-go/RSA-go"
)

func main() {
	// Geração do par de chaves RSA
	priv, pub := encryptRSA.GenerateRsaKeyPair()

	// Exportação das chaves para formato PEM
	privPEM := encryptRSA.ExportRsaPrivateKeyAsPemStr(priv)
	pubPEM, err := encryptRSA.ExportRsaPublicKeyAsPemStr(pub)
	if err != nil {
		log.Fatalf("error exporting public key: %v", err)
	}

	// Teste de exportação e importação das chaves
	privParsed, err := encryptRSA.ParseRsaPrivateKeyFromPemStr(privPEM)
	if err != nil {
		log.Fatalf("error importing private key: %v", err)
	}
	pubParsed, err := encryptRSA.ParseRsaPublicKeyFromPemStr(pubPEM)
	if err != nil {
		log.Fatalf("error importing public key: %v", err)
	}

	// Inicialização do JWT com as chaves importadas
	jwtToken := encryptRSA.NewJWT(privParsed, pubParsed)

	// Criação e validação do token
	token, err := jwtToken.CreateRS512(time.Hour, "12345678")
	if err != nil {
		log.Fatalf("error creating token: %v", err)
	}
	fmt.Println("TOKEN:", token)

	content, err := jwtToken.Validate(token)
	if err != nil {
		log.Fatalf("error validating token: %v", err)
	}
	fmt.Println("CONTENT:", content)
}
