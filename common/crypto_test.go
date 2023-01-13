package common

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
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
func Test_loadPublicKey(t *testing.T) {
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "public.pem")
	assert.Nil(t, LoadPublicKey())
	assert.NotNil(t, pubKey)
	assert.Equal(t, 512, pubKey.Size()) // PubKey of 4096 RSA is 512 bytes
}
func Test_loadPublicKeyNotFound(t *testing.T) {
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "public.nonexistent")
	err := LoadPublicKey()
	assert.NotNil(t, err)
	assert.True(t, os.IsNotExist(err))
}
func Test_loadPublicKeyNotAKey(t *testing.T) {
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "public.fake")
	assert.NoError(t, os.WriteFile(PubKeyPath, []byte("THIS IS NOT A KEY"), 0777))
	err := LoadPublicKey()
	assert.NotNil(t, err)
	assert.Contains(t, "file does not contain PEM data", err.Error())
	assert.NoError(t, os.Remove(PubKeyPath))
}
func Test_loadPublicKeyIsPrvate(t *testing.T) {
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "private.pem")
	err := LoadPublicKey()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "structure error")
}

// //////////////////////
// Test LoadPrivateKey //
// //////////////////////
func Test_loadPrivateKey(t *testing.T) {
	PrivateKeyPath = filepath.Join(filepath.Clean("../test"), "private.pem")
	assert.Nil(t, LoadPrivateKey())
	assert.NotNil(t, privKey)
	assert.Equal(t, 512, privKey.Size()) // PrivateKey of 4096 RSA is 512 bytes
}
func Test_loadPrivateKeyNotFound(t *testing.T) {
	PrivateKeyPath = filepath.Join(filepath.Clean("../test"), "private.nonexistent")
	err := LoadPrivateKey()
	assert.NotNil(t, err)
	assert.True(t, os.IsNotExist(err))
}
func Test_loadPrivateKeyNotAKey(t *testing.T) {
	PrivateKeyPath = filepath.Join(filepath.Clean("../test"), "private.fake")
	assert.NoError(t, os.WriteFile(PrivateKeyPath, []byte("THIS IS NOT A KEY"), 0777))
	err := LoadPrivateKey()
	assert.NotNil(t, err)
	assert.Contains(t, "file does not contain PEM data", err.Error())
	assert.NoError(t, os.Remove(PrivateKeyPath))
}
func Test_loadPrivateKeyIsPublic(t *testing.T) {
	PrivateKeyPath = filepath.Join(filepath.Clean("../test"), "public.pem")
	err := LoadPrivateKey()
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "structure error")
}

// /////////////////////////
// Test Encrypt / decrypt //
// /////////////////////////
func Test_encryptDecrypt(t *testing.T) {
	// 1. Arrange
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "public.pem")
	PrivateKeyPath = filepath.Join(filepath.Clean("../test"), "private.pem")
	assert.Nil(t, LoadPublicKey())
	assert.Nil(t, LoadPrivateKey())

	// 2. Act
	fileToCopy := filepath.Join(filepath.Clean("../test"), "test_config.yaml")
	fileToEncrypt := filepath.Join(filepath.Clean("../test"), "some_test.file")
	contentsOriginal, err := os.ReadFile(fileToCopy)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(fileToEncrypt, contentsOriginal, 0777))
	f, err := os.OpenFile(fileToEncrypt, os.O_RDWR, 0777)
	defer f.Close()
	assert.NoError(t, err)
	encrypted, err := Encrypt(f)
	assert.NoError(t, err)
	// ... aaaand directly decrypt back
	contentsDecrypted, err := decrypt(encrypted)
	assert.NoError(t, err)

	// 3. Assert
	assert.Equal(t, contentsOriginal, contentsDecrypted)
	_, err = os.Stat(fileToEncrypt)
	assert.Error(t, err)
	assert.True(t, os.IsNotExist(err))
}
func Test_encryptInvalidKeyLength(t *testing.T) {
	type tc struct {
		errPart string
		bytes   int
	}
	tests := []tc{
		{"message too long for RSA public key size", 1024},
		{"key size must be 512 bytes", 2048},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("Encrypt with %d bits key", tt.bytes), func(t *testing.T) {
			PubKeyPath = filepath.Join(filepath.Clean("../test"), fmt.Sprintf("public%d.pem", tt.bytes))
			assert.Nil(t, LoadPublicKey())
			fake, err := os.Create("tmp")
			assert.NoError(t, err)
			_, err = Encrypt(fake)
			assert.ErrorContains(t, err, tt.errPart)
		})
	}
}
func Test_decryptInvalidContents(t *testing.T) {
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "public.pem")
	assert.Nil(t, LoadPublicKey())
	tmpFile, err := os.Create("tmp")
	assert.NoError(t, err)
	tmpStr := []byte("This is the end.")
	_, err = tmpFile.Write(tmpStr)
	assert.NoError(t, err)
	enc, err := Encrypt(tmpFile)
	assert.NoError(t, err)

	// override all content bytes with 'x'
	for i := 0; i < len(enc)-512; i++ {
		enc[i] = 'x'
	}
	result, err := decrypt(enc)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "message authentication failed")

}
func Test_decryptInvalidKey(t *testing.T) {
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "public.pem")
	assert.Nil(t, LoadPublicKey())
	tmpFile, err := os.Create("tmp")
	assert.NoError(t, err)
	tmpStr := []byte("This is the end.")
	_, err = tmpFile.Write(tmpStr)
	assert.NoError(t, err)
	enc, err := Encrypt(tmpFile)
	assert.NoError(t, err)

	// create new random key, Encrypt it and attach
	keyConfig, _ := keyloader.GenerateKey(
		xchacha20poly1305.CipherName, // The recommended cipher
		"log_key",
		false,
		time.Now(),
	)
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(keyConfig.String()))
	copy(enc[len(enc)-512:], encKey)

	// Decryption
	result, err := decrypt(enc)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "message authentication failed")

}
func Test_decryptDamagedKey(t *testing.T) {
	PubKeyPath = filepath.Join(filepath.Clean("../test"), "public.pem")
	assert.Nil(t, LoadPublicKey())
	tmpFile, err := os.Create("tmp")
	assert.NoError(t, err)
	tmpStr := []byte("This is the end.")
	_, err = tmpFile.Write(tmpStr)
	assert.NoError(t, err)
	enc, err := Encrypt(tmpFile)
	assert.NoError(t, err)

	// Decryption
	result, err := decrypt(enc[:len(enc)-5])
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "decryption error")
}

func Test_extractKey(t *testing.T) {
	k, err := symmecrypt.NewRandomKey(xchacha20poly1305.CipherName)
	assert.NoError(t, err)
	ks, err := k.String()
	assert.NoError(t, err)
	keyBytes := []byte(fmt.Sprintf(`{"key":"%s"}`, ks))

	result, err := extractKey(keyBytes)
	assert.NoError(t, err)

	resultString, err := result.String()
	assert.NoError(t, err)
	assert.Equal(t, ks, resultString)
}
func Test_extractKeyDamaged(t *testing.T) {
	k, err := symmecrypt.NewRandomKey(xchacha20poly1305.CipherName)
	assert.NoError(t, err)
	ks, err := k.String()
	assert.NoError(t, err)
	keyBytes := []byte(fmt.Sprintf(`{"key":"%s"}`, ks))

	result, err := extractKey(keyBytes[:len(keyBytes)-5])
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "unexpected end of JSON input")
}
