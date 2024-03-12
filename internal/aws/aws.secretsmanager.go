package aws

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
	"encoding/base64"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// smSession represents the AWS Secrets Manager Session.
var smSession *secretsmanager.SecretsManager

// verifyEcrSession test if session is available and if not, create a new one.
func verifySmSession() {
	verifyAwsSession()
	if smSession == nil {
		smSession = secretsmanager.New(sess)
	}
}

// GetEncryptionKey loads an encryption key from Secrets Manager.
// In Secrets Manager it is stored base64-encoded, so it gets decoded and returned as binary byte slice.
func GetEncryptionKey(secretName string) ([]byte, error) {
	verifySmSession()
	result, err := smSession.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
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
