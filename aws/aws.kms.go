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
	"context"
	"github.com/sigstore/sigstore/pkg/signature"
	kmssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

// CreateKmsSigner creates a signer instance from a KMS ARN
func CreateKmsSigner(uri string) (signature.Signer, error) {
	verifyAwsSession()
	return kmssigner.LoadSignerVerifier(context.Background(), uri)
}
