package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
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

// loadPrivateKey reads and parses a private key from a file
func loadPrivateKey() error {
	keyBytes, err := os.ReadFile(Seal.PrivKeyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return errors.New("file does not contain PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	privKey = key.(*rsa.PrivateKey)
	return err
}

// CreatePKISigner uses the private key to create a signature.Signer instance
func CreatePKISigner() (signature.Signer, error) {
	err := loadPrivateKey()
	if err != nil {
		return nil, err
	}
	return signature.LoadSigner(privKey, crypto.SHA512)
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

// decrypt detaches the encryption key, decrypts it with a private key and use it to decrypt the payload
func decrypt(encryptedData []byte) ([]byte, error) {
	firstKeyIndex := len(encryptedData) - KeySizeBit
	keyBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encryptedData[firstKeyIndex:])
	if err != nil {
		return nil, err
	}
	key, err := extractKey(keyBytes)
	if err != nil {
		return nil, err
	}
	decrypted, err := key.Decrypt(encryptedData[:firstKeyIndex])
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// extractKey loads a key from JSON without configstore
func extractKey(keyBytes []byte) (symmecrypt.Key, error) {
	item := struct {
		Key string `json:"key"`
	}{}
	err := json.Unmarshal(keyBytes, &item)
	if err != nil {
		return nil, err
	}
	return symmecrypt.NewKey(xchacha20poly1305.CipherName, item.Key)
}
