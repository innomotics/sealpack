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
	"sealpack/aws"
	"sealpack/shared"
	"strings"
)

var createKmsSigner = aws.CreateKmsSigner

type SealConfig struct {
	PrivKeyPath          string
	RecipientPubKeyPaths []string
	Public               bool
	Seal                 bool
	HashingAlgorithm     string
	Files                []string
	ImageNames           []string
	Images               []*shared.ContainerImage
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
		return createKmsSigner(Seal.PrivKeyPath)
	}
	// TODO: other potential signing modules
	return shared.CreatePKISigner(Seal.PrivKeyPath)
}
