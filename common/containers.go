package common

import (
	"context"
	"fmt"
	"github.com/containers/podman/v4/cmd/podman/registry"
	"github.com/containers/podman/v4/pkg/domain/entities"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
)

// SaveImage with podman's Image registry.
// Functionality implemented according to "podman image save"
func SaveImage(img *ContainerImage) (result []byte, finalErr error) {
	var done = false
	pipePath, cleanup, err := setupPipe()
	if err != nil {
		return nil, err
	}
	if cleanup != nil {
		defer func() {
			errc := cleanup()
			if done {
				writeErr := <-errc
				if writeErr != nil && finalErr == nil {
					finalErr = writeErr
				}
			}
		}()
	}
	saveOpts := entities.ImageSaveOptions{
		Format: "oci-archive",
		Output: pipePath,
	}
	if err = registry.ImageEngine().Save(context.Background(), img.String(), nil, saveOpts); err == nil {
		done = true
	}
	if result, err = os.ReadFile(pipePath); err != nil {
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
