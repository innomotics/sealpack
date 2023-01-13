package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/sigstore/sigstore/pkg/signature"
	"os"
	"time"
)

const (
	KeySizeBit = 512
)

var (
	pubKey  *rsa.PublicKey
	privKey *rsa.PrivateKey
)

// LoadPublicKey reads and parses a public key from a file
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("file does not contain PEM data")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PublicKey), nil
}

// LoadPrivateKey reads and parses a private key from a file
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("file does not contain PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}

// CreatePKISigner uses the private key to create a signature.Signer instance
func CreatePKISigner() (signature.Signer, error) {
	pKey, err := LoadPrivateKey(Seal.PrivKeyPath)
	if err != nil {
		return nil, err
	}
	return signature.LoadSigner(pKey, GetConfiguredHashAlgorithm(Seal.HashingAlgorithm))
}

func CreatePKIVerifier() (signature.Verifier, error) {
	pubKey, err := LoadPublicKey(Unseal.SigningKeyPath)
	if err != nil {
		return nil, err
	}
	return signature.LoadVerifier(pubKey, GetConfiguredHashAlgorithm(Unseal.HashingAlgorithm))
}

// Encrypt the contents of an os.File with a random key and retrieve the results as []byte
// The asymmetrically encrypted encryption key is attached als the last [ KeySizeBit ] bytes
func Encrypt(unencrypted []byte) ([]byte, []byte, error) {
	// No error possible with this static configuration
	keyConfig, _ := keyloader.GenerateKey(
		xchacha20poly1305.CipherName, // The recommended cipher
		"log_key",
		false,
		time.Now(),
	)
	// No error possible with this static configuration
	key, _ := keyloader.NewKey(keyConfig)
	encrypted, err := key.Encrypt(unencrypted)
	if err != nil {
		return nil, nil, err
	}
	return encrypted, []byte(keyConfig.Key), nil
}

// extractKey loads a key from JSON without configstore
func TryUnsealKey(encrypted []byte, key *rsa.PrivateKey) (symmecrypt.Key, error) {
	keyBytes, err := rsa.DecryptPKCS1v15(rand.Reader, key, encrypted)
	if err != nil {
		return nil, err
	}
	return symmecrypt.NewKey(xchacha20poly1305.CipherName, string(keyBytes))
}
