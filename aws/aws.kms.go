package aws

import (
	"github.com/sigstore/sigstore/pkg/signature"
	kmssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

func CreateKmsSigner(uri string) (signature.Signer, error) {
	return kmssigner.LoadSignerVerifier(uri)
}
