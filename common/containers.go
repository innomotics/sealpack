package common

import (
	"context"
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-containerregistry/pkg/crane"
	"os"
	"path/filepath"
	"sealpack/shared"
)

const (
	LocalRegistry    = "local"
	ContainerDSocket = "/run/containerd/containerd.sock"
)

// SaveImage with podman's Image registry.
// Functionality implemented according to "podman image save"
func SaveImage(img *shared.ContainerImage) (result []byte, err error) {
	tmpdir := filepath.Join(os.TempDir(), "crane.dl", img.ToFileName())
	if err = os.MkdirAll(filepath.Dir(tmpdir), 0777); err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpdir)
	image, err := crane.Pull(img.String())
	if err != nil {
		return nil, err
	}
	if err = crane.Save(image, img.String(), tmpdir); err != nil {
		return nil, err
	}
	if result, err = os.ReadFile(tmpdir); err != nil {
		return nil, err
	}
	return result, err
}

// ImportImages loads all images from the default folder and imports them.
// After importing, the images are being deleted.
func ImportImages() error {
	containerPath := filepath.Join(Unseal.OutputPath, shared.ContainerImagePrefix)
	origRegs, err := os.ReadDir(containerPath)
	if err != nil {
		return err
	}
	for _, o := range origRegs {
		images, err := os.ReadDir(filepath.Join(containerPath, o.Name()))
		if err != nil {
			return err
		}
		for _, image := range images {
			imgFileName := filepath.Join(containerPath, o.Name(), image.Name())
			if err = ImportImage(imgFileName, shared.ParseContainerImage(o.Name(), image.Name())); err != nil {
				return err
			}
			if err = os.Remove(imgFileName); err != nil {
				return err
			}
		}
	}
	return os.RemoveAll(containerPath)
}

// ImportImage imports one OCI image into a local containerd storage or a provided registry.
func ImportImage(ociPath string, img *shared.ContainerImage) error {
	fmt.Println(ociPath, Unseal.TargetRegistry, img)
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
		imgs, err := client.Import(namespaces.WithNamespace(context.Background(), "default"), tarStream)
		if err != nil {
			return err
		}
		fmt.Println("Images imported:", imgs)
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
