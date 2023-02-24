package common

import (
	"context"
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
	LocalRegistry    = "local"
	ContainerDSocket = "/run/containerd/containerd.sock"
)

// SaveImage with podman's Image registry.
// Functionality implemented according to "podman image save"
func SaveImage(img *shared.ContainerImage) (result *os.File, err error) {
	tmpdir := filepath.Join(os.TempDir(), "crane.dl", img.ToFileName())
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

func CleanupImages() error {
	return os.RemoveAll(filepath.Join(os.TempDir(), "crane.dl"))
}

func ParseContainerImage(name string) *shared.ContainerImage {
	name = strings.TrimPrefix(name, "/")
	registry := DefaultRegistry
	regPattern := regexp.MustCompile("^([^/]+.[a-z]+)/")
	regDomain := regPattern.FindString(name)
	if regDomain != "" {
		registry = strings.TrimSuffix(regDomain, "/")
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
		if _, err := os.Stat(ContainerDSocket); os.IsNotExist(err) || os.IsPermission(err) {
			return err
		}
		client, err := containerd.New(ContainerDSocket)
		if err != nil {
			return err
		}
		defer client.Close()
		tarStream, err := os.Open(ociPath)
		defer tarStream.Close()
		_, err = client.Import(namespaces.WithNamespace(context.Background(), "default"), tarStream)
		if err != nil {
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
