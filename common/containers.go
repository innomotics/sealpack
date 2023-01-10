package common

import (
	"fmt"
	"github.com/google/go-containerregistry/pkg/crane"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"sealpack/shared"
)

// SaveImage with podman's Image registry.
// Functionality implemented according to "podman image save"
func SaveImage(img *shared.ContainerImage) (result []byte, err error) {
	tmpfile, err := os.CreateTemp("", "crane.dl")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())
	if _, err = io.Copy(tmpfile, os.Stdin); err != nil {
		return nil, err
	}
	image, err := crane.Pull(img.String())
	if err != nil {
		return nil, err
	}
	if err = crane.SaveOCI(image, tmpfile.Name()); err != nil {
		return nil, err
	}
	if err = tmpfile.Close(); err != nil {
		return nil, err
	}
	if result, err = os.ReadFile(tmpfile.Name()); err != nil {
		return nil, err
	}
	return result, err
}

// setupPipe taken from https://github.com/containers/podman/blob/main/cmd/podman/images/save.go
func setupPipe() (string, func() <-chan error, error) {
	errc := make(chan error)
	var pipeDir, pipePath string
	var err error
	if pipeDir, err = os.MkdirTemp(os.TempDir(), "pipeDir"); err != nil {
		return "", nil, err
	}
	pipePath = filepath.Join(pipeDir, "saveio")
	if err = unix.Mkfifo(pipePath, 0600); err != nil {
		if e := os.RemoveAll(pipeDir); e != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Removing named pipe: %q", e)
		}
		return "", nil, fmt.Errorf("creating named pipe: %w", err)
	}
	go func() {
		var fpipe *os.File
		fpipe, err = os.Open(pipePath)
		if err != nil {
			errc <- err
			return
		}
		_, err = io.Copy(os.Stdout, fpipe)
		_ = fpipe.Close()
		errc <- err
	}()
	return pipePath, func() <-chan error {
		if e := os.RemoveAll(pipeDir); e != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Removing named pipe: %q", e)
		}
		return errc
	}, nil
}
