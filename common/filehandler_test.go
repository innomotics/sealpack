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
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Test_WriteFile(t *testing.T) {
	// Arrange
	Seal.Output = filepath.Join(TestFilePath, "test.out")
	assert.NoFileExists(t, Seal.Output)
	content := []byte("Hold your breath and count to 10.")

	// Act
	err := WriteFileBytes(content)
	assert.Nil(t, err)

	// Assert
	assert.FileExists(t, Seal.Output)
	defer os.Remove(Seal.Output)
	cnt, err := os.ReadFile(Seal.Output)
	assert.Nil(t, err)
	assert.Equal(t, content, cnt)
}

func Test_WriteFileStdout(t *testing.T) {
	// Arrange
	Seal.Output = "-"
	content := []byte("Hold your breath and count to 10.")
	var err error
	stdout, err = os.CreateTemp("/tmp", "test.tmp")
	defer func() { stdout = os.Stdout }()
	defer os.Remove(stdout.Name())
	assert.Nil(t, err)

	// Act
	err = WriteFileBytes(content)
	assert.Nil(t, err)
	_, err = stdout.Seek(0, 0)
	assert.Nil(t, err)

	// Assert
	cnt, err := io.ReadAll(stdout)
	assert.Nil(t, err)
	assert.Equal(t, content, cnt)
}

func Test_WriteFileS3(t *testing.T) {
	// Arrange
	Seal.Output = "s3://somebucket/someprefix/some.object"
	content := []byte("Hold your breath and count to 10.")
	uploadS3 = func(reader io.ReadSeeker, uri string) error {
		bts, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.Equal(t, content, bts)
		assert.Equal(t, Seal.Output, uri)
		return nil
	}

	// Act
	err := WriteFileBytes(content)
	assert.Nil(t, err)
}

func Test_WriteFileUnallowed(t *testing.T) {
	// Arrange
	Seal.Output = "/sys/class/some.object"
	content := []byte("Hold your breath and count to 10.")
	// Act
	err := WriteFileBytes(content)
	assert.Error(t, err)
}

func Test_ContainerImage(t *testing.T) {
	image := "cr.siemens.com/mathias.haimerl/sealpack:latest"
	ci := ParseContainerImage(image)
	assert.Equal(t,
		strings.Join(
			[]string{ContainerImagePrefix, ci.Registry, ci.Name + ":" + ci.Tag + OCISuffix},
			"/",
		),
		ci.ToFileName(),
	)
	assert.Equal(t, strings.Join(
		[]string{ci.Registry, ci.Name + ":" + ci.Tag},
		"/",
	),
		ci.String(),
	)
}
