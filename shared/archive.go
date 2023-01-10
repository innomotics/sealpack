package shared

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"io"
	"time"
)

// Envelope is the package with headers and so on
type Envelope struct {
	PayloadEncrypted []byte
	HashAlgorithm    crypto.Hash
	NumReceivers     uint16
	ReceiverKeys     [][]byte
}

// ToBytes provides an Envelope as Bytes
func (e *Envelope) ToBytes() []byte {
	result := append(
		[]byte(EnvelopeMagicBytes),
		byte(e.HashAlgorithm),
		uint8(e.NumReceivers>>8),
		uint8(e.NumReceivers&0xff),
	)
	for _, key := range e.ReceiverKeys {
		result = append(result, key...)
	}
	return result
}

const (
	EnvelopeMagicBytes = "\xDBIPC" // ASCII sum of "ECS" = 333(octal) or DB(hex)
)

type Archive struct {
	compressWriter io.Writer
	tarWriter      *tar.Writer
	//	tarOut     *bufio.Writer
	buffer *bytes.Buffer
}

/**
 * TODO: Make compressWriter compression algorithm flexible
 */

// CreateArchive opens a stream of writers (tar to gzip to buffer).
// Bytes added to the stream will be added to the tar.gz archive.
// It can be retrieved through the buffer as byte slice.
func CreateArchive() *Archive {
	arc := &Archive{
		buffer: new(bytes.Buffer),
	}
	arc.compressWriter = gzip.NewWriter(arc.buffer)
	arc.tarWriter = tar.NewWriter(arc.compressWriter)
	return arc
}

// Finalize closes the tar and gzip writers and retrieves the archive.
// In addition
func (arc *Archive) Finalize() ([]byte, error) {
	// Finish archive packaging and get contents
	var err error
	_, closeable := arc.compressWriter.(interface{}).(io.Closer)
	if closeable {
		if err = arc.compressWriter.(io.Closer).Close(); err != nil {
			return nil, err
		}
	}
	if err = arc.tarWriter.Close(); err != nil {
		return nil, err
	}
	return arc.buffer.Bytes(), err
}

// AddToArchive adds a new file identified by its name to the tar.gz archive.
// The contents are added as byte slices.
func (arc *Archive) AddToArchive(imgName string, contents []byte) error {
	return WriteToTar(arc.tarWriter, &imgName, contents)
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
