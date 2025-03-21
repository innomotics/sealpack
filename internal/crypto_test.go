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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const TestFilePath = "../test"

// /////////////////////
// Test CreateSigner //
// /////////////////////

func Test_CreateSigner(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean(TestFilePath), "private.pem")
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.Nil(t, err)
	sig, err := CreateSigner(privateKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, sig)
	pub, err := sig.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, privKey.(*rsa.PrivateKey).Public(), pub) // PubKey of 4096 RSA is 512 bytes
}

func Test_CreateSignerAWS(t *testing.T) {
	old := createKmsSigner
	defer func() { createKmsSigner = old }()
	createKmsSigner = func(uri string) (signature.Signer, error) {
		assert.Contains(t, uri, KmsPrefix)
		return &aws.SignerVerifier{}, nil
	}
	privateKeyPath := "awskms:///foo:bar:fnord"
	sig, err := CreateSigner(privateKeyPath)
	assert.Nil(t, err)
	assert.Implements(t, (*signature.Signer)(nil), sig)
}

// /////////////////////
// Test LoadPublicKey //
// /////////////////////
func Test_LoadPublicKey(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, 512, pubKey.(*rsa.PublicKey).Size()) // PubKey of 4096 RSA is 512 bytes
}
func Test_LoadPublicKeyECDSA(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "ec-public.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, pubKey)
	assert.IsType(t, ed25519.PublicKey{}, pubKey) // ECDSA PrivateKey
}
func Test_LoadPublicKeyASN1(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "asn1-public.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, pubKey)
	assert.IsType(t, &ecdsa.PublicKey{}, pubKey) // ECDSA PrivateKey
}
func Test_LoadPublicKeyPKCS1(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "pkcs1-public.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, 128, pubKey.(*rsa.PublicKey).Size()) // PubKey of 4096 RSA is 512 bytes
}
func Test_LoadPublicKeyNotFound(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.nonexistent")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.NotNil(t, err)
	assert.True(t, os.IsNotExist(err))
	assert.Nil(t, pubKey)
}
func Test_LoadPublicKeyNotAKey(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.fake")
	assert.NoError(t, os.WriteFile(pubKeyPath, []byte("THIS IS NOT A KEY"), 0777))
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.NotNil(t, err)
	assert.Contains(t, "file does not contain PEM data", err.Error())
	assert.Nil(t, pubKey)
	assert.NoError(t, os.Remove(pubKeyPath))
}
func Test_LoadPublicKeyIsPrivate(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "private.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "structure error")
	assert.Nil(t, pubKey)
}

// //////////////////////
// Test LoadPrivateKey //
// //////////////////////
func Test_LoadPrivateKey(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "private.pem")
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
	assert.Equal(t, 512, privKey.(*rsa.PrivateKey).Size()) // PrivateKey of 4096 RSA is 512 bytes
}
func Test_LoadPrivateKeyECDSA(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "ec-private.pem")
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
	assert.IsType(t, ed25519.PrivateKey{}, privKey) // ECDSA PrivateKey
}
func Test_LoadPrivateKeyASN1(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "asn1-private.pem")
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
	assert.IsType(t, &ecdsa.PrivateKey{}, privKey) // ECDSA PrivateKey
}
func Test_LoadPrivateKeyPKCS1(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "pkcs1-private.pem")
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, privKey)
	assert.Equal(t, 128, privKey.(*rsa.PrivateKey).Size()) // PrivateKey of 4096 RSA is 512 bytes
}
func Test_LoadPrivateKeyNotFound(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "private.nonexistent")
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.NotNil(t, err)
	assert.True(t, os.IsNotExist(err))
	assert.Nil(t, privKey)
}
func Test_LoadPrivateKeyNotAKey(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "private.fake")
	assert.NoError(t, os.WriteFile(privateKeyPath, []byte("THIS IS NOT A KEY"), 0777))
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.NotNil(t, err)
	assert.Contains(t, "file does not contain PEM data", err.Error())
	assert.Nil(t, privKey)
	assert.NoError(t, os.Remove(privateKeyPath))
}
func Test_LoadPrivateKeyIsPublic(t *testing.T) {
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "structure error")
	assert.Nil(t, privKey)
}

// /////////////////////////
// Test Encrypt / decrypt //
// /////////////////////////
func Test_EncryptDecrypt(t *testing.T) {
	// 1. Arrange
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	privateKeyPath := filepath.Join(filepath.Clean("../test"), "private.pem")
	encrypter, err := GetEncrypter(pubKeyPath)
	assert.Nil(t, err)
	decrypter, err := GetDecrypter(privateKeyPath)
	assert.Nil(t, err)

	// 2. Act
	contentsOriginal := []byte("This is a confidential message")
	// Encrypt Contents, then seal key ...
	encrypted, symKey, err := Encrypt(contentsOriginal)
	assert.NoError(t, err)
	encKey, err := encrypter.EncryptMessage(symKey)
	assert.NoError(t, err)
	// ... aaaand directly decrypt back
	keyDecrypted, err := TryUnsealKey(encKey, decrypter)
	assert.NoError(t, err)
	contentsDecrypted, err := keyDecrypted.Decrypt(encrypted)
	assert.NoError(t, err)

	// 3. Assert
	assert.Equal(t, contentsOriginal, contentsDecrypted)
}
func Test_DecryptInvalidContents(t *testing.T) {
	enc, keyBytes, err := Encrypt([]byte("This is the end."))
	assert.NoError(t, err)

	// override all content bytes with 'x'
	for i := 0; i < len(enc); i++ {
		enc[i] = 'x'
	}
	key, err := symmecrypt.NewKey(xchacha20poly1305.CipherName, string(keyBytes))
	assert.NoError(t, err)
	result, err := key.Decrypt(enc)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "message authentication failed")

}
func Test_DecryptInvalidKey(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	encrypter, err := GetEncrypter(pubKeyPath)
	assert.Nil(t, err)
	privKeyPath := filepath.Join(filepath.Clean("../test"), "private.pem")
	decrypter, err := GetDecrypter(privKeyPath)
	assert.Nil(t, err)

	// create new random key, Encrypt it and attach
	keyConfig, _ := keyloader.GenerateKey(
		xchacha20poly1305.CipherName, // The recommended cipher
		"log_key",
		false,
		time.Now(),
	)
	encKey, err := encrypter.EncryptMessage([]byte(keyConfig.String()))
	assert.NoError(t, err)

	// Decryption
	result, err := TryUnsealKey(encKey, decrypter)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "unable to create AEAD key")

}
func Test_DecryptDamagedKey(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	encrypter, err := GetEncrypter(pubKeyPath)
	assert.Nil(t, err)
	privKeyPath := filepath.Join(filepath.Clean("../test"), "private.pem")
	decrypter, err := GetDecrypter(privKeyPath)
	assert.Nil(t, err)
	_, key, err := Encrypt([]byte("This is the end."))
	assert.NoError(t, err)
	enc, err := encrypter.EncryptMessage(key)
	assert.Nil(t, err)

	// Decryption
	result, err := TryUnsealKey(enc[:len(enc)-5], decrypter)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "decryption error")
}

func Test_TryUnsealKeyEC(t *testing.T) {

}
