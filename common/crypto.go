package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/sigstore/sigstore/pkg/signature"
	"io"
	"os"
	"time"
)

const (
	KeySizeBytes = 512
)

var (
	pubKey  *rsa.PublicKey
	privKey *rsa.PrivateKey
)

// loadPrivateKey reads and parses a public key from a file
func loadPublicKey() error {
	keyBytes, err := os.ReadFile(Unseal.PrivkeyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return errors.New("file does not contain PEM data")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pubKey = key.(*rsa.PublicKey)
	return nil
}

// loadPrivateKey reads and parses a private key from a file
func loadPrivateKey() error {
	keyBytes, err := os.ReadFile(Seal.PubkeyPath)
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

func CreatePKISigner() (signature.Signer, error) {
	err := loadPrivateKey()
	if err != nil {
		return nil, err
	}
	return signature.LoadSigner(privKey, crypto.SHA3_512)
}

// encrypt the contents of an os.File with a random key and retrieve the results as []byte
// The asymmetrically encrypted encryption key is attached als the last [ KeySizeBytes ] bytes
func encrypt(unencrypted *os.File) ([]byte, error) {
	// No error possible with this static configuration
	keyConfig, _ := keyloader.GenerateKey(
		xchacha20poly1305.CipherName, // The recommended cipher
		"log_key",
		false,
		time.Now(),
	)
	// No error possible with this static configuration
	key, _ := keyloader.NewKey(keyConfig)
	_, err := unencrypted.Seek(0, 0)
	if err != nil {
		return nil, err
	}
	bts, err := io.ReadAll(unencrypted)
	if err != nil {
		return nil, err
	}
	defer os.Remove(unencrypted.Name())
	encrypted, err := key.Encrypt(bts)
	if err != nil {
		return nil, err
	}
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(keyConfig.String()))
	if err != nil {
		return nil, err
	}
	if len(encKey) != KeySizeBytes {
		return nil, fmt.Errorf("key size must be %d bytes", KeySizeBytes)
	}
	return append(encrypted, encKey...), nil
}

// decrypt detaches the encryption key, decrypts it with a private key and use it to decrypt the payload
func decrypt(encryptedData []byte) ([]byte, error) {
	firstKeyIndex := len(encryptedData) - KeySizeBytes
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

// load a key from JSON without configstore
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
