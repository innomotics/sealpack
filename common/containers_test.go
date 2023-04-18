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
	"os"
	"path/filepath"
	"sealpack/shared"
	"testing"
)

func Test_SaveImageAndCleanup(t *testing.T) {
	ci := ParseContainerImage("alpine:3.17")
	assert.Equal(t, "docker.io", ci.Registry)
	assert.Equal(t, "alpine", ci.Name)
	assert.Equal(t, "3.17", ci.Tag)
	file, err := SaveImage(ci)
	assert.NoError(t, err)
	stat, err := file.Stat()
	assert.NoError(t, err)
	tmpFolder := filepath.Join(os.TempDir(), TmpFolderName)
	ls, err := os.ReadDir(tmpFolder)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ls))
	assert.Equal(t, ".images", ls[0].Name())
	assert.False(t, stat.IsDir())
	// alpine should be 3-4 MB
	assert.True(t, stat.Size() > 3000000 && stat.Size() < 4000000)
	assert.DirExists(t, tmpFolder)
	assert.FileExists(t, filepath.Join(tmpFolder, ".images", ci.Registry, stat.Name()))
	assert.NoError(t, CleanupImages())
	assert.NoDirExists(t, tmpFolder)
	assert.NoFileExists(t, filepath.Join(tmpFolder, ".images", ci.Registry, stat.Name()))
}

func Test_FullParseContainerImage(t *testing.T) {
	input := "registry.example.com/unit/group/project/someimage:sometag"
	result := ParseContainerImage(input)
	assert.Equal(t, "registry.example.com", result.Registry)
	assert.Equal(t, "unit/group/project/someimage", result.Name)
	assert.Equal(t, "sometag", result.Tag)
	assert.Equal(t, input, result.String())
	assert.Equal(t, filepath.Join(shared.ContainerImagePrefix, input+shared.OCISuffix), result.ToFileName())
}
