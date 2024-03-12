package internal

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
	"sealpack/internal/aws"
	"strings"
)

var createKmsSigner = aws.CreateKmsSigner

const (
	DefaultRegistry = "docker.io"
)

type PackageContent interface {
	PackagePath() string
}

// ReadConfiguration searches for the latest configuration file and reads the contents.
// The contents are parsed as a slice of PackageContent from a JSON or YAML file.
func ReadConfiguration(fileName string, files *[]string, images *[]*ContainerImage) error {
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
		*files = contents.Files
	}
	if contents.Images != nil {
		imgList := make([]*ContainerImage, len(contents.Images))
		for i := 0; i < len(contents.Images); i++ {
			imgList[i] = ParseContainerImage(contents.Images[i])
		}
		*images = imgList
	}
	return nil
}
