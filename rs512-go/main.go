package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

func main() {
	// Crie as chaves
	priv, pub := GenerateRsaKeyPair()

	// Exporte as chaves para  pem string
	priv_pem := ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, err := ExportRsaPublicKeyAsPemStr(pub)
	if err != nil {
		fmt.Println(err)
	}

	// Importe as chaves para pem string
	priv_parsed, err := ParseRsaPrivateKeyFromPemStr(priv_pem)
	if err != nil {
		fmt.Println(err)
	}
	pub_parsed, err := ParseRsaPublicKeyFromPemStr(pub_pem)
	if err != nil {
		fmt.Println(err)
	}
	// Exporte as novas chaves importadas
	priv_parsed_pem := ExportRsaPrivateKeyAsPemStr(priv_parsed)
	pub_parsed_pem, err := ExportRsaPublicKeyAsPemStr(pub_parsed)
	if err != nil {
		fmt.Println(err)
	}

	jwtToken := NewJWT([]byte(priv_parsed_pem), []byte(pub_parsed_pem))

	// 1. Crie um novo JWT token.
	tok, err := jwtToken.Create(time.Hour, "iago josé laurentino alves")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("TOKEN:", tok)

	// 2. Valide um JWT token existente.
	content, err := jwtToken.Validate(tok)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("CONTENT:", content)
}

type JWT struct {
	privateKey []byte
	publicKey  []byte
}

func NewJWT(privateKey []byte, publicKey []byte) JWT {
	return JWT{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (j JWT) Create(ttl time.Duration, content interface{}) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(j.privateKey)
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["dat"] = content             // seus dados.
	claims["exp"] = now.Add(ttl).Unix() // o tempo de expiração em que token deve ser descartado.
	claims["iat"] = now.Unix()          // a hora que o token foi usado.
	claims["nbf"] = now.Unix()          // o tempo antes do token ser descartado.

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS512, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func (j JWT) Validate(token string) (interface{}, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return "", fmt.Errorf("validate: parse key: %w", err)
	}

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims["dat"], nil
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break
	}
	return nil, errors.New("key type is not RSA")
}
