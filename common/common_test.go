package common

import (
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

const TestFilePath = "../test"

func Test_CreateSigner(t *testing.T) {
	Seal = &SealConfig{
		HashingAlgorithm: "SHA512",
		PrivKeyPath:      filepath.Join(filepath.Clean(TestFilePath), "private.pem"),
	}
	privKey, err := LoadPrivateKey(Seal.PrivKeyPath)
	assert.Nil(t, err)
	sig, err := CreateSigner()
	assert.Nil(t, err)
	assert.NotNil(t, sig)
	pub, err := sig.PublicKey()
	assert.Nil(t, err)
	assert.Equal(t, privKey.Public(), pub) // PubKey of 4096 RSA is 512 bytes
}
func Test_CreateSignerAWS(t *testing.T) {
	old := createKmsSigner
	defer func() { createKmsSigner = old }()
	createKmsSigner = func(uri string) (signature.Signer, error) {
		assert.Contains(t, uri, "awskms:///")
		return &aws.SignerVerifier{}, nil
	}
	Seal = &SealConfig{
		HashingAlgorithm: "SHA512",
		PrivKeyPath:      "awskms:///foo:bar:fnord",
	}
	sig, err := CreateSigner()
	assert.Nil(t, err)
	assert.Implements(t, (*signature.Signer)(nil), sig)
}
func Test_CreateSignerIncompatibleAlgo(t *testing.T) {
	Seal = &SealConfig{
		HashingAlgorithm: "SHA224", // Incompatible with RSA
		PrivKeyPath:      filepath.Join(filepath.Clean(TestFilePath), "private.pem"),
	}
	sig, err := CreateSigner()
	assert.Nil(t, sig)
	assert.Contains(t, "invalid hash function specified", err.Error())
}
