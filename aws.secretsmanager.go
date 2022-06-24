package main

import (
	"encoding/base64"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// smSession represents the AWS Secrets Manager Session.
var smSession *secretsmanager.SecretsManager

// getEncryptionKey loads the AES encryption key from Secrets Manager.
// In Secrets Manager it is stored base64-encoded, so it gets decoded and returned as 32-bit binary byte slice.
func getEncryptionKey() ([]byte, error) {
	result, err := smSession.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(SecretName),
	})
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 32)
	_, err = base64.StdEncoding.Decode(buffer, []byte(*result.SecretString))
	if err != nil {
		return nil, err
	}
	return buffer, err
}
