package common

import (
	"github.com/sigstore/sigstore/pkg/signature"
	"sealpack/aws"
	"strings"
)

type PackageContent interface {
	PackagePath() string
}

type Signer struct {
	Signer *signature.SignerVerifier
}

func CreateSigner() (signature.Signer, error) {
	if strings.HasPrefix(Seal.PrivKeyPath, "awskms:///") {
		return aws.CreateKmsSigner(Seal.PrivKeyPath)
	}
	// TODO: other potential signing modules
	return CreatePKISigner()
}
