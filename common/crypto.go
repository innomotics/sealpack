package common

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
	"crypto/x509"
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

// PrivateKey is defined as any structure implementing crypto.Signer and crypto.Decrypter
type PrivateKey interface {
	crypto.Signer
	crypto.Decrypter
}

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
	key, err := parsePublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PublicKey), nil
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
func LoadPrivateKey(path string) (PrivateKey, error) {
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
func parsePrivateKey(block []byte) (PrivateKey, error) {
	var key any
	key, err := x509.ParsePKCS1PrivateKey(block)
	if err == nil {
		return key.(PrivateKey), nil
	}
	key, err = x509.ParsePKCS8PrivateKey(block)
	if err == nil {
		return key.(PrivateKey), nil
	}
	key, err = x509.ParseECPrivateKey(block)
	if err != nil {
		return nil, err
	}
	return key.(PrivateKey), err
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
func TryUnsealKey(encrypted []byte, key PrivateKey) (symmecrypt.Key, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ECDSA Keys cannot be used for decryption")
	}
	keyBytes, err := rsa.DecryptPKCS1v15(rand.Reader, rsaKey, encrypted)
	if err != nil {
		return nil, err
	}
	return symmecrypt.NewKey(xchacha20poly1305.CipherName, string(keyBytes))
}
