package common

import (
	"github.com/sigstore/sigstore/pkg/signature"
	"sealpack/aws"
	"sealpack/shared"
	"strings"
)

type SealConfig struct {
	PrivKeyPath          string
	RecipientPubKeyPaths []string
	Seal                 bool
	HashingAlgorithm     string
	Files                []string
	ImageNames           []string
	Images               []shared.ContainerImage
	Output               string
}

type UnsealConfig struct {
	PrivKeyPath      string
	SigningKeyPath   string
	OutputPath       string
	HashingAlgorithm string
	TargetRegistry   string
}

const (
	DefaultRegistry = "docker.io"
	DefaultTag      = "latest"
)

var (
	SealedFile string
	Seal       *SealConfig
	Unseal     *UnsealConfig
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
