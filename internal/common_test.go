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
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func Test_ReadConfigurationEmptyJSON(t *testing.T) {
	var files []string
	var images []*ContainerImage
	configFile := filepath.Join(os.TempDir(), "content-config.json")
	jsonConfig := []byte(`{}`)
	assert.NoError(t, os.WriteFile(configFile, jsonConfig, 0777))
	defer os.Remove(configFile)
	assert.NoError(t, ReadConfiguration(configFile, &files, &images))
	assert.Nil(t, files)
	assert.Nil(t, images)
}

func Test_ReadConfigurationInvalidJSON(t *testing.T) {
	var files []string
	var images []*ContainerImage
	configFile := filepath.Join(os.TempDir(), "content-config.json")
	jsonConfig := []byte(`{invalid}`)
	assert.NoError(t, os.WriteFile(configFile, jsonConfig, 0777))
	defer os.Remove(configFile)
	assert.ErrorContains(t, ReadConfiguration(configFile, &files, &images), "invalid character")
}

func Test_ReadConfigurationJSON(t *testing.T) {
	var files []string
	var images []*ContainerImage
	configFile := filepath.Join(os.TempDir(), "content-config.json")
	jsonConfig := []byte(`{"images":["alpine:latest","cr.example.com/foo/bar/fnord:3.14"],"files":["abc.txt","test.log","/var/log/syslog"]}`)
	assert.NoError(t, os.WriteFile(configFile, jsonConfig, 0777))
	defer os.Remove(configFile)
	assert.NoError(t, ReadConfiguration(configFile, &files, &images))
	assert.Equal(t, 3, len(files))
	assert.Equal(t, 2, len(images))
}

func Test_ReadConfigurationInvalidYAML(t *testing.T) {
	var files []string
	var images []*ContainerImage
	configFile := filepath.Join(os.TempDir(), "content-config.yaml")
	yamlConfig := []byte(`images:
foo:bar`)
	assert.NoError(t, os.WriteFile(configFile, yamlConfig, 0777))
	defer os.Remove(configFile)
	assert.ErrorContains(t, ReadConfiguration(configFile, &files, &images), "could not find expected ':'")
}

func Test_ReadConfigurationYAML(t *testing.T) {
	var files []string
	var images []*ContainerImage
	configFile := filepath.Join(os.TempDir(), "content-config.yaml")
	yamlConfig := []byte(`images:
- 'alpine:latest'
- 'cr.example.com/foo/bar/fnord:3.14'
files:
- abc.txt
- test.log
- /var/log/syslog`)
	assert.NoError(t, os.WriteFile(configFile, yamlConfig, 0777))
	defer os.Remove(configFile)
	assert.NoError(t, ReadConfiguration(configFile, &files, &images))
	assert.Equal(t, 3, len(files))
	assert.Equal(t, 2, len(images))
}

func Test_ReadConfigurationInvalidType(t *testing.T) {
	var files []string
	var images []*ContainerImage
	configFile := filepath.Join(os.TempDir(), "content-config.fnord")
	yamlConfig := []byte(`no content needed`)
	assert.NoError(t, os.WriteFile(configFile, yamlConfig, 0777))
	defer os.Remove(configFile)
	assert.ErrorContains(t, ReadConfiguration(configFile, &files, &images), "invalid file type: .fnord")
}

func Test_ReadConfigurationNonExisting(t *testing.T) {
	var files []string
	var images []*ContainerImage
	configFile := filepath.Join(os.TempDir(), "nonexisting.yaml")
	assert.ErrorContains(t, ReadConfiguration(configFile, &files, &images), "no such file or directory")
}
