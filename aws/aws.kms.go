package aws

import (
	"context"
	"github.com/sigstore/sigstore/pkg/signature"
	kmssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

// CreateKmsSigner creates a signer instance from a KMS ARN
func CreateKmsSigner(uri string) (signature.Signer, error) {
	verifyAwsSession()
	return kmssigner.LoadSignerVerifier(context.Background(), uri)
}
