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
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
	ContainerDSocket  = ""
	containerDClient  *containerd.Client
	containerDContext context.Context
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
				return io.EOF
			}
			return nil
		})
		if err != nil && err != io.EOF {
			return "", err
		}
	}
	return ContainerDSocket, nil
}

// SaveImage with from a registry to a local OCI file.
func SaveImage(img *ContainerImage) (result *os.File, err error) {
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
func ParseContainerImage(name string) *ContainerImage {
	name = strings.TrimPrefix(name, "/")
	registry := DefaultRegistry
	// Pattern tries to find a domain in the image name ('.'-separated string with '/' only at the end)
	regPattern := regexp.MustCompile("^([^/]+(\\.[^/]+)+)/")
	regDomain := regPattern.FindString(name)
	if regDomain != "" {
		firstSlash := strings.Index(name, "/")
		registry = name[:firstSlash]
		name = name[firstSlash+1:]
	}
	imgParts := strings.Split(strings.TrimSuffix(name, OCISuffix), ":")
	if len(imgParts) < 2 {
		imgParts = append(imgParts, "latest")
	}
	return &ContainerImage{
		Registry: registry,
		Name:     imgParts[0],
		Tag:      imgParts[1],
	}
}

// getContainerDClient creates a client for accessing a local containerD instance
func getContainerDClient() (*containerd.Client, context.Context, error) {
	var err error
	var sock string
	var nsList []string
	if containerDContext == nil {
		sock, err = GetContainerDSocket()
		if err != nil {
			return nil, nil, err
		}
		if _, err = os.Stat(sock); os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil, err
		}
		containerDClient, err = containerd.New(sock)
		if err != nil {
			return nil, nil, err
		}
		nsList, err = containerDClient.NamespaceService().List(context.Background())
		if err != nil {
			return nil, nil, err
		}
		if !contains(nsList, Unseal.Namespace) {
			err = fmt.Errorf("invalid namespace")
			return nil, nil, err
		}
		containerDContext = namespaces.WithNamespace(context.Background(), Unseal.Namespace)
	}
	return containerDClient, containerDContext, nil
}

// ImportImage imports one OCI image into a local containerd storage or a provided registry.
func ImportImage(tarReader io.ReadCloser, tag *name.Tag) (newImport bool, err error) {
	switch Unseal.TargetRegistry {
	case LocalRegistry:
		return importLocal(tarReader, tag)
	default:
		return importToRegistry(tarReader, tag)
	}
}

// importLocal imports an image to a locally running containerd instance
func importLocal(tarReader io.ReadCloser, tag *name.Tag) (newImport bool, err error) {
	var oldImg containerd.Image
	var newImg []images.Image
	client, ctx, err := getContainerDClient()
	if err != nil {
		return false, err
	}
	oldImg, _ = client.GetImage(ctx, tag.Name())
	newImg, err = client.Import(ctx, tarReader)
	if err != nil {
		return
	}
	if oldImg != nil && oldImg.Target().Digest != newImg[0].Target.Digest {
		newImport = true
	}
	err = client.Close()
	return
}

// importToRegistry imports a container image into a target registry
func importToRegistry(tarReader io.ReadCloser, tag *name.Tag) (newImport bool, err error) {
	var img v1.Image
	var digBefore v1.Hash
	var digAfter string
	tag.Repository, err = name.NewRepository(Unseal.TargetRegistry)
	if err != nil {
		return
	}
	img, err = tarball.Image(func() (io.ReadCloser, error) {
		return tarReader, nil
	}, tag)
	if err != nil {
		return
	}
	digBefore, err = img.Digest()
	err = crane.Push(img, tag.Name())
	if err != nil {
		return
	}
	digAfter, err = crane.Digest(tag.Name())
	if digBefore.String() != digAfter {
		newImport = true
	}
	return
}

// RemoveAll multiple images from a registry or containerD instance defined by slice
func RemoveAll(tags []*name.Tag) (err error) {
	for _, tag := range tags {
		switch Unseal.TargetRegistry {
		case LocalRegistry:
			client, ctx, err := getContainerDClient()
			if err != nil {
				return err
			}
			return client.ImageService().Delete(ctx, tag.Name())
		default:
			return crane.Delete(tag.Name())
		}
	}
	return
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
