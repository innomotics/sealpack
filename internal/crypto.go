package internal

/*
 * Sealpack
 *
 * Copyright (c) Innomotics GmbH, 2023
 *
 * Authors:
 *  Mathias Haimerl <mathias.haimerl@siemens.com>
 *
 * This work is licensed under the terms of the Apache 2.0 license.
 * See the LICENSE.txt file in the top-level directory.
 *
 * SPDX-License-Identifier:	Apache-2.0
 */

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/innomotics/sealpack/internal/aws"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/sigstore/sigstore/pkg/signature"
	"io"
	"os"
	"strings"
	"time"
)

const KmsPrefix = "awskms:///"

// Encrypter interface to encrypt messages
type Encrypter interface {
	EncryptMessage(message []byte) ([]byte, error)
	KeySize() int
}

// RSAEncrypter implements Encrypter interface with RSA keys
type RSAEncrypter struct {
	pubKey *rsa.PublicKey
}

// EncryptMessage encrypts a message using RSA
func (enc *RSAEncrypter) EncryptMessage(message []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, enc.pubKey, message, nil)
}

// KeySize provides the length of an RSA key
func (enc *RSAEncrypter) KeySize() int {
	return enc.pubKey.Size()
}

// NewRSAEncrypter creates an instance of an RSAEncrypter
func NewRSAEncrypter(keyPath string) (*RSAEncrypter, error) {
	var err error
	var plainKey crypto.PublicKey
	if plainKey, err = LoadPublicKey(keyPath); err != nil {
		return nil, err
	}
	if recPubKey, ok := plainKey.(*rsa.PublicKey); ok {
		return &RSAEncrypter{
			pubKey: recPubKey,
		}, nil
	}
	return nil, fmt.Errorf("RSAEncrypter: not RSA public key")
}

// GetEncrypter provides a new Encrypter instance
func GetEncrypter(path string) (Encrypter, error) {
	if strings.HasPrefix(path, KmsPrefix) {
		return aws.NewKMSEncrypter(strings.TrimPrefix(path, KmsPrefix))
	}
	return NewRSAEncrypter(path)
}

// Decrypter interface to decrypt messages
type Decrypter interface {
	DecryptMessage(message []byte) ([]byte, error)
	KeySize() int
}

// RSADecrypter implements Decrypter interface with RSA keys
type RSADecrypter struct {
	privKey *rsa.PrivateKey
}

// DecryptMessage encrypts a message using RSA
func (dec *RSADecrypter) DecryptMessage(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, dec.privKey, ciphertext, nil)
}

// KeySize provides the length of an RSA key
func (dec *RSADecrypter) KeySize() int {
	return dec.privKey.Size()
}

// NewRSADecrypter creates an instance of an RSADecrypter
func NewRSADecrypter(keyPath string) (*RSADecrypter, error) {
	var err error
	var plainKey crypto.PrivateKey
	if plainKey, err = LoadPrivateKey(keyPath); err != nil {
		return nil, err
	}
	if recPrivKey, ok := plainKey.(*rsa.PrivateKey); ok {
		return &RSADecrypter{
			privKey: recPrivKey,
		}, nil
	}
	return nil, fmt.Errorf("RSAEncrypter: not RSA private key")
}

// GetDecrypter provides a new Decrypter instance
func GetDecrypter(path string) (Decrypter, error) {
	if strings.HasPrefix(path, KmsPrefix) {
		return aws.NewKMSDecrypter(strings.TrimPrefix(path, KmsPrefix))
	}
	return NewRSADecrypter(path)
}

// CreateSigner chooses the correct signature.Signer depending on the private key string
func CreateSigner(privateKeyPath string) (signature.Signer, error) {
	if strings.HasPrefix(privateKeyPath, KmsPrefix) {
		return createKmsSigner(privateKeyPath)
	}
	return CreatePKISigner(privateKeyPath)
}

// CreateVerifier chooses the correct signature.Verifier depending on the private key string
func CreateVerifier(publicKeyPath string) (signature.Verifier, error) {
	if strings.HasPrefix(publicKeyPath, KmsPrefix) {
		return createKmsVerifier(publicKeyPath)
	}
	return CreatePKIVerifier(publicKeyPath)
}

// LoadPublicKey reads and parses a public key from a file
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("file does not contain PEM data")
	}
	key, err := parsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(crypto.PublicKey), nil
}

// parsePublicKey tries to parse the byte slice as PKCS1 and PKIX key and provides it back
func parsePublicKey(block []byte) (any, error) {
	key, err := x509.ParsePKIXPublicKey(block)
	if err == nil {
		return key, nil
	}
	return x509.ParsePKCS1PublicKey(block)
}

// LoadPrivateKey reads and parses a private key from a file
func LoadPrivateKey(path string) (interface{}, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("file does not contain PEM data")
	}
	return parsePrivateKey(block.Bytes)
}

// parsePrivateKey tries to parse the byte slice as PKCS1, PKCS8 and EC key and provides it back
func parsePrivateKey(block []byte) (interface{}, error) {
	var key any
	key, err := x509.ParsePKCS1PrivateKey(block)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKCS8PrivateKey(block)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParseECPrivateKey(block)
	if err != nil {
		return nil, err
	}
	return key, err
}

// CreatePKISigner uses the private key to create a signature.Signer instance
func CreatePKISigner(pkeyPath string) (signature.Signer, error) {
	pKey, err := LoadPrivateKey(pkeyPath)
	if err != nil {
		return nil, err
	}
	return signature.LoadSigner(pKey, crypto.SHA256)
}

// CreatePKIVerifier builds a verifier based on a public key
func CreatePKIVerifier(skeyPath string) (signature.Verifier, error) {
	pubKey, err := LoadPublicKey(skeyPath)
	if err != nil {
		return nil, err
	}
	return signature.LoadVerifier(pubKey, crypto.SHA256)
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

func EncryptWriter(w io.Writer) (string, io.WriteCloser) {
	keyConfig, _ := keyloader.GenerateKey(
		xchacha20poly1305.CipherName, // The recommended cipher
		"log_key",
		false,
		time.Now(),
	)
	key, _ := keyloader.NewKey(keyConfig)
	return keyConfig.Key, symmecrypt.NewWriter(w, key)
}

// TryUnsealKey loads a key from JSON without configstore
func TryUnsealKey(encrypted []byte, decrypter Decrypter) (symmecrypt.Key, error) {
	keyBytes, err := decrypter.DecryptMessage(encrypted)
	if err != nil {
		return nil, err
	}
	return symmecrypt.NewKey(xchacha20poly1305.CipherName, string(keyBytes))
}

// AddKeys encrypts the symmetric key for every receiver and attaches them to the envelope
func AddKeys(recipientPubKeyPaths []string, envelope *Envelope, plainKey []byte) error {
	var err error
	var encrypter Encrypter
	envelope.ReceiverKeys = [][]byte{}
	envelope.ReceiverKeys = make([][]byte, len(recipientPubKeyPaths))
	for iKey, recipientPubKeyPath := range recipientPubKeyPaths {
		encrypter, err = GetEncrypter(recipientPubKeyPath)
		if err != nil {
			return err
		}
		if envelope.ReceiverKeys[iKey], err = encrypter.EncryptMessage(plainKey); err != nil {
			return err
		}
		if len(envelope.ReceiverKeys[iKey]) != encrypter.KeySize() {
			return fmt.Errorf("key size must be %d bits", encrypter.KeySize())
		}
	}
	return nil
}
