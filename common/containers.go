package common

import (
	"github.com/google/go-containerregistry/pkg/crane"
	"os"
	"path/filepath"
	"sealpack/shared"
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
