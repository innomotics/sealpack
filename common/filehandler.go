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
	"bytes"
	"os"
	"sealpack/aws"
	"strings"
)

var uploadS3 = aws.S3UploadArchive
var stdout = os.Stdout

// WriteFileBytes allows for writing a byte slice to a regular file, S3 bucket or stdout
func WriteFileBytes(contents []byte) error {
	if strings.HasPrefix(Seal.Output, aws.S3UriPrefix) {
		return uploadS3(bytes.NewReader(contents), Seal.Output)
	} else {
		var of *os.File
		var err error
		if Seal.Output == "-" {
			of = stdout
		} else {
			of, err = os.Create(Seal.Output)
			if err != nil {
				return err
			}
			defer of.Close()
		}
		_, err = of.Write(contents)
		return err
	}
}

// NewOutputFile creates a new output file depending on the type of output target
func NewOutputFile() (*os.File, error) {
	if strings.HasPrefix(strings.ToLower(Seal.Output), aws.S3UriPrefix) {
		return os.CreateTemp("", "")
	}
	if Seal.Output == "-" {
		return stdout, nil
	}
	return os.Create(Seal.Output)
}

// CleanupFileWriter cleans up temporary files and performs post-finish operations
func CleanupFileWriter(f *os.File) error {
	if strings.HasPrefix(strings.ToLower(Seal.Output), aws.S3UriPrefix) {
		tmp, err := os.Open(f.Name())
		if err != nil {
			return err
		}
		if err = uploadS3(tmp, Seal.Output); err != nil {
			return err
		}
		return os.Remove(f.Name())
	}
	return nil
}
