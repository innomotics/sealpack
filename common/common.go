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
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"sealpack/aws"
	"strings"
)

var createKmsSigner = aws.CreateKmsSigner

type SealConfig struct {
	PrivKeyPath          string
	RecipientPubKeyPaths []string
	Public               bool
	Seal                 bool
	HashingAlgorithm     string
	CompressionAlgorithm string
	ContentFileName      string
	Files                []string
	ImageNames           []string
	Images               []*ContainerImage
	Output               string
}

type UnsealConfig struct {
	PrivKeyPath      string
	SigningKeyPath   string
	OutputPath       string
	HashingAlgorithm string
	TargetRegistry   string
	Namespace        string
}

const (
	DefaultRegistry = "docker.io"
)

type PackageContent interface {
	PackagePath() string
}

// ReadConfiguration searches for the latest configuration file and reads the contents.
// The contents are parsed as a slice of PackageContent from a JSON or YAML file.
func ReadConfiguration(fileName string, sealCfg *SealConfig) error {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	var contents ArchiveContents
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".json":
		err = json.Unmarshal(data, &contents)
		break
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &contents)
		break
	default:
		err = fmt.Errorf("invalid file type: %s", filepath.Ext(fileName))
	}
	if err != nil {
		return err
	}
	if contents.Files != nil {
		sealCfg.Files = contents.Files
	}
	if contents.Images != nil {
		sealCfg.Images = make([]*ContainerImage, len(contents.Images))
		for i := 0; i < len(contents.Images); i++ {
			sealCfg.Images[i] = ParseContainerImage(contents.Images[i])
		}
	}
	return nil
}
