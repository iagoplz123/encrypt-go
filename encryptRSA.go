package encryptRSA

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

// JWT armazena as chaves privadas e públicas para criação e validação de tokens
type JWT struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewJWT inicializa uma estrutura JWT com as chaves privada e pública
func NewJWT(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) JWT {
	return JWT{privateKey, publicKey}
}

// CreateRS256 gera um novo token JWT com duração `ttl` e dados `content`
func (j JWT) CreateRS256(ttl time.Duration, content interface{}) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"dat": content,             // seus dados.
		"exp": now.Add(ttl).Unix(), // o tempo de expiração em que token deve ser descartado.
		"iat": now.Unix(),          // a hora que o token foi usado.
		"nbf": now.Unix(),          // o tempo antes do token ser descartado.
	}

	token256 := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token256.SignedString(j.privateKey)
}

// CreateRS384 gera um novo token JWT com duração `ttl` e dados `content`
func (j JWT) CreateRS384(ttl time.Duration, content interface{}) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"dat": content,             // seus dados.
		"exp": now.Add(ttl).Unix(), // o tempo de expiração em que token deve ser descartado.
		"iat": now.Unix(),          // a hora que o token foi usado.
		"nbf": now.Unix(),          // o tempo antes do token ser descartado.
	}

	token384 := jwt.NewWithClaims(jwt.SigningMethodRS384, claims)

	return token384.SignedString(j.privateKey)
}

// CreateRS512 gera um novo token JWT com duração `ttl` e dados `content`
func (j JWT) CreateRS512(ttl time.Duration, content interface{}) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"dat": content,             // seus dados.
		"exp": now.Add(ttl).Unix(), // o tempo de expiração em que token deve ser descartado.
		"iat": now.Unix(),          // a hora que o token foi usado.
		"nbf": now.Unix(),          // o tempo antes do token ser descartado.
	}

	token512 := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	return token512.SignedString(j.privateKey)
}

// Validate valida um token JWT existente e retorna seu conteúdo
func (j JWT) Validate(token string) (interface{}, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims["dat"], nil
	}
	return nil, errors.New("invalid token")
}

// GenerateRsaKeyPair gera um par de chaves RSA
func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("error generating RSA key pair: %v", err)
	}
	return privKey, &privKey.PublicKey
}

// ExportRsaPrivateKeyAsPemStr exporta a chave privada RSA para o formato PEM
func ExportRsaPrivateKeyAsPemStr(privKey *rsa.PrivateKey) string {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(privKeyPEM)
}

// ParseRsaPrivateKeyFromPemStr importa uma chave privada RSA a partir do formato PEM
func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ExportRsaPublicKeyAsPemStr exporta a chave pública RSA para o formato PEM
func ExportRsaPublicKeyAsPemStr(pubKey *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("error when exporting public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	return string(pubKeyPEM), nil
}

// ParseRsaPublicKeyFromPemStr importa uma chave pública RSA a partir do formato PEM
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to decrypt PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error when parsing PEM public key: %w", err)
	}
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		return rsaPub, nil
	}
	return nil, errors.New("public key is not of type RSA")
}
