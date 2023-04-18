package common

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
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"sealpack/shared"
	"testing"
)

const TestFilePath = "../test"

func Test_CreateSigner(t *testing.T) {
	Seal = &SealConfig{
		HashingAlgorithm: "SHA512",
		PrivKeyPath:      filepath.Join(filepath.Clean(TestFilePath), "private.pem"),
	}
	privKey, err := shared.LoadPrivateKey(Seal.PrivKeyPath)
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
