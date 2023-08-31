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
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestNewOutputFile(t *testing.T) {
	tests := []struct {
		name        string
		want        string
		outputParam string
	}{
		{"Standard file", "/tmp/foo\\.bar", "/tmp/foo.bar"},
		{"S3 Object", "/tmp/[0-9]+", "s3://home/test/Documents/foo.bar"},
		{"Uppercase S3 object", "/tmp/[0-9]+", "S3://home/test/Documents/foo.bar"},
		{"Standard file", stdout.Name(), "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Seal = &SealConfig{Output: tt.outputParam}
			got, err := NewOutputFile()
			assert.NoError(t, err)
			assert.Regexp(t, tt.want, got.Name(), "NewOutputFile()")
		})
	}
}

func TestCleanupFileWriter(t *testing.T) {
	tests := []struct {
		name          string
		outputParam   string
		uploadCalled  bool
		expectedError string
	}{
		{"Standard file", "/foo/bar.fnord", false, ""},
		{"S3 Object", "s3://home/test/Documents/foo.bar", true, ""},
		{"Uppercase S3 object", "S3://home/test/Documents/foo.bar", true, ""},
		{"Standard file", "-", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := uploadS3
			uploadCalled := false
			uploadS3 = func(reader io.ReadSeeker, uri string) error {
				uploadCalled = true
				assert.Equal(t, tt.outputParam, uri)
				return nil
			}
			Seal = &SealConfig{Output: tt.outputParam}
			tmpFile, err := os.CreateTemp("", "foo.bar")
			assert.NoError(t, err)
			assert.NoError(t, CleanupFileWriter(tmpFile))
			assert.Equal(t, tt.uploadCalled, uploadCalled)
			if !tt.uploadCalled {
				assert.NoError(t, os.Remove(tmpFile.Name()))
			}
			uploadS3 = tmp
		})
	}
}

func TestCleanupFileWriter_Errors(t *testing.T) {
	Seal = &SealConfig{Output: "s3://foo/bar"}
	tmpFile := os.NewFile(uintptr(syscall.Stdin), "/tmp/does/not/exist")
	result := CleanupFileWriter(tmpFile)
	assert.ErrorContains(t, result, "no such file or directory")
}

func TestCleanupFileWriter_ErrorsUpload(t *testing.T) {
	tmp := uploadS3
	uploadS3 = func(reader io.ReadSeeker, uri string) error {
		return fmt.Errorf("faked upload error here")
	}
	Seal = &SealConfig{Output: "s3://foo/bar"}
	tmpFile, err := os.CreateTemp("", "foo.bar")
	assert.NoError(t, err)
	result := CleanupFileWriter(tmpFile)
	assert.ErrorContains(t, result, "faked upload error here")
	uploadS3 = tmp
}
