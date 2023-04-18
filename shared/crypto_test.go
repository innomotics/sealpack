package shared

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
	"crypto/rand"
	"crypto/rsa"
	"github.com/ovh/symmecrypt"
	"github.com/ovh/symmecrypt/ciphers/xchacha20poly1305"
	"github.com/ovh/symmecrypt/keyloader"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// /////////////////////
// Test LoadPublicKey //
// /////////////////////
func Test_LoadPublicKey(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	assert.NotNil(t, pubKey)
	assert.Equal(t, 512, pubKey.Size()) // PubKey of 4096 RSA is 512 bytes
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
func Test_LoadPublicKeyIsPrvate(t *testing.T) {
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
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	privKey, err := LoadPrivateKey(privateKeyPath)
	assert.Nil(t, err)

	// 2. Act
	contentsOriginal := []byte("This is a confidential message")
	// Encrypt Contents, then seal key ...
	encrypted, symKey, err := Encrypt(contentsOriginal)
	assert.NoError(t, err)
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, symKey)
	assert.NoError(t, err)
	// ... aaaand directly decrypt back
	keyDecrypted, err := TryUnsealKey(encKey, privKey)
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
	result, err := key.Decrypt(enc)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "message authentication failed")

}
func Test_DecryptInvalidKey(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	privKeyPath := filepath.Join(filepath.Clean("../test"), "private.pem")
	privKey, err := LoadPrivateKey(privKeyPath)
	assert.Nil(t, err)

	// create new random key, Encrypt it and attach
	keyConfig, _ := keyloader.GenerateKey(
		xchacha20poly1305.CipherName, // The recommended cipher
		"log_key",
		false,
		time.Now(),
	)
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(keyConfig.String()))

	// Decryption
	result, err := TryUnsealKey(encKey, privKey)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "unable to create AEAD key")

}
func Test_DecryptDamagedKey(t *testing.T) {
	pubKeyPath := filepath.Join(filepath.Clean("../test"), "public.pem")
	pubKey, err := LoadPublicKey(pubKeyPath)
	assert.Nil(t, err)
	privKeyPath := filepath.Join(filepath.Clean("../test"), "private.pem")
	privKey, err := LoadPrivateKey(privKeyPath)
	assert.Nil(t, err)
	_, key, err := Encrypt([]byte("This is the end."))
	assert.NoError(t, err)
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, key)
	assert.Nil(t, err)

	// Decryption
	result, err := TryUnsealKey(enc[:len(enc)-5], privKey)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "decryption error")
}
