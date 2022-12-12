package common

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"time"
)

var (
	gzipWriter *gzip.Writer
	tarWriter  *tar.Writer
	//	tarOut     *bufio.Writer
	buffer *bytes.Buffer
)

// CreateArchive opens a stream of writers (tar to gzip to buffer).
// Bytes added to the stream will be added to the tar.gz archive.
// It can be retrieved through the buffer as byte slice.
func CreateArchive() {
	buffer = new(bytes.Buffer)
	gzipWriter = gzip.NewWriter(buffer)
	tarWriter = tar.NewWriter(gzipWriter)
}

// Finalize closes the tar and gzip writers.
func Finalize() []byte {
	gzipWriter.Close()
	tarWriter.Close()
	return buffer.Bytes()
}

// WriteToTar adds a file to a writer using a filename and a byte slice with contents to be written.
func WriteToTar(w *tar.Writer, filename *string, contents []byte) error {
	if err := w.WriteHeader(&tar.Header{
		Name:    *filename,
		Size:    int64(len(contents)),
		Mode:    0755,
		ModTime: time.Now(),
	}); err != nil {
		return err
	}
	_, err := w.Write(contents)
	return err
}

// addToArchive adds a new file identified by its name to the tar.gz archive.
// The contents and the accompanying signature are added as byte slices.
// The signature's filename is the filename with .sig suffix.
func addToArchive(imgName string, contents []byte, signature []byte) error {
	// 1. Add the OCI image
	if err := WriteToTar(tarWriter, &imgName, contents); err != nil {
		return err
	}
	fmt.Println("Added " + imgName)
	// 2. Add signature
	sigName := imgName + ".sig"
	if err := WriteToTar(tarWriter, &sigName, signature); err != nil {
		return err
	}
	fmt.Println("Added signature for " + imgName)
	return nil
}
