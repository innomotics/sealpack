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
	"context"
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-containerregistry/pkg/crane"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sealpack/shared"
	"strings"
)

const (
	LocalRegistry          = "local"
	TmpFolderName          = "crane.dl"
	ContainerDSocketFolder = "/run"
	ContainerDSocketFile   = "containerd.sock"
	ContainerDDefaultNs    = "default"
)

var (
	ContainerDSocket = ""
)

// GetContainerDSocket searched for a containerD socket in the /run folder
func GetContainerDSocket() (string, error) {
	if ContainerDSocket == "" {
		err := filepath.Walk(ContainerDSocketFolder, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.HasSuffix(path, ContainerDSocketFile) && (info.Mode()&os.ModeSocket) > 0 {
				ContainerDSocket = path
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	return ContainerDSocket, nil
}

// SaveImage with from a registry to a local OCI file.
func SaveImage(img *shared.ContainerImage) (result *os.File, err error) {
	tmpdir := filepath.Join(os.TempDir(), TmpFolderName, img.ToFileName())
	if err = os.MkdirAll(filepath.Dir(tmpdir), 0777); err != nil {
		return nil, err
	}
	image, err := crane.Pull(img.String())
	if err != nil {
		return nil, err
	}
	if err = crane.Save(image, img.String(), tmpdir); err != nil {
		return nil, err
	}
	if result, err = os.Open(tmpdir); err != nil {
		return nil, err
	}
	return result, err
}

// CleanupImages removes the temp folder where container images are stored.
func CleanupImages() error {
	return os.RemoveAll(filepath.Join(os.TempDir(), TmpFolderName))
}

// ParseContainerImage takes a string describing an image and parses the registry, name and tag out of it.
func ParseContainerImage(name string) *shared.ContainerImage {
	name = strings.TrimPrefix(name, "/")
	registry := DefaultRegistry
	regPattern := regexp.MustCompile("^([^/]+(\\.[^/]+)+)/")
	regDomain := regPattern.FindString(name)
	if regDomain != "" {
		firstSlash := strings.Index(name, "/")
		registry = name[:firstSlash]
		name = name[firstSlash+1:]
	}
	imgParts := strings.Split(strings.TrimSuffix(name, shared.OCISuffix), ":")
	if len(imgParts) < 2 {
		imgParts = append(imgParts, "latest")
	}
	return &shared.ContainerImage{
		Registry: registry,
		Name:     imgParts[0],
		Tag:      imgParts[1],
	}
}

// ImportImages loads all images from the default folder and imports them.
// After importing, the images are being deleted.
func ImportImages() error {
	pathPrefix := filepath.Join(Unseal.OutputPath, shared.ContainerImagePrefix)
	if err := filepath.Walk(pathPrefix, func(image string, info fs.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(info.Name(), shared.OCISuffix) {
			if err = ImportImage(image, ParseContainerImage(strings.TrimPrefix(image, pathPrefix))); err != nil {
				return err
			}
			if err = os.Remove(image); err != nil {
				return err
			}
		}
		return err
	}); err != nil {
		return err
	}
	return os.RemoveAll(pathPrefix)
}

// ImportImage imports one OCI image into a local containerd storage or a provided registry.
func ImportImage(ociPath string, img *shared.ContainerImage) error {
	switch Unseal.TargetRegistry {
	case LocalRegistry:
		sock, err := GetContainerDSocket()
		if err != nil {
			return err
		}
		if _, err = os.Stat(sock); os.IsNotExist(err) || os.IsPermission(err) {
			return err
		}
		client, err := containerd.New(sock)
		if err != nil {
			return err
		}
		nsList, err := client.NamespaceService().List(context.Background())
		if err != nil {
			return err
		}
		if !contains(nsList, Unseal.Namespace) {
			return fmt.Errorf("invalid namespace")
		}
		tarStream, err := os.Open(ociPath)
		if err != nil {
			return err
		}
		_, err = client.Import(namespaces.WithNamespace(context.Background(), Unseal.Namespace), tarStream)
		if err != nil {
			return err
		}
		if err = tarStream.Close(); err != nil {
			return err
		}
		if err = client.Close(); err != nil {
			return err
		}
		break
	default:
		img.Registry = Unseal.TargetRegistry
		image, err := crane.Load(ociPath)
		if err != nil {
			return err
		}
		return crane.Push(image, img.String())
	}
	return nil
}

// contains is designed as generic slice contents search function
func contains[Q comparable](haystack []Q, needle Q) bool {
	for _, val := range haystack {
		if val == needle {
			return true
		}
	}
	return false
}
