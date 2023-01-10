package common

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

// ArchiveContents describes all contents for an archive to provide them as a single file.
type ArchiveContents struct {
	Files  []string         `json:"files"`
	Images []ContainerImage `json:"images"`
}

// ContainerImage describes a container image uniquely
type ContainerImage struct {
	Registry string `json:"registry"`
	Name     string `json:"name"`
	Tag      string `json:"tag"`
}

// String creates the image URI form the parts.
func (i *ContainerImage) String() string {
	return i.Registry + "/" + i.Name + ":" + i.Tag
}

// ToFileName creates a file name to store the image archive in.
func (i *ContainerImage) ToFileName() string {
	return filepath.Join(ContainerImagePrefix, i.Registry, i.Name+":"+i.Tag+".oci")
}

// Envelope is the package with headers and so on
type Envelope struct {
	payloadEncrypted []byte
	hashAlgorithm    crypto.Hash
	numReceivers     uint16
	receiverKeys     [][]byte
}

// ToBytes provides an Envelope as Bytes
func (e *Envelope) ToBytes() []byte {
	result := append(
		[]byte(EnvelopeMagicBytes),
		byte(e.hashAlgorithm),
		uint8(e.numReceivers>>8),
		uint8(e.numReceivers&0xff),
	)
	for _, key := range e.receiverKeys {
		result = append(result, key...)
	}
	return result
}

const (
	ContainerImagePrefix = ".images"
	EnvelopeMagicBytes   = "\xDBIPC" // ASCII sum of "ECS" = 333(octal) or DB(hex)
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
	envelope := Envelope{
		hashAlgorithm: GetConfiguredHashAlgorithm(),
	}
	_, closeable := arc.compressWriter.(interface{}).(io.Closer)
	if closeable {
		if err = arc.compressWriter.(io.Closer).Close(); err != nil {
			return nil, err
		}
	}
	if err = arc.tarWriter.Close(); err != nil {
		return nil, err
	}
	// Now create encryption key and seal them for all recipients
	var symKey []byte
	if envelope.payloadEncrypted, symKey, err = encrypt(arc.buffer.Bytes()); err != nil {
		return nil, err
	}
	envelope.numReceivers = uint16(len(Seal.RecipientPubKeyPaths))
	envelope.receiverKeys = make([][]byte, 0, envelope.numReceivers)
	for iKey, recipientPubKeyPath := range Seal.RecipientPubKeyPaths {
		var recPubKey *rsa.PublicKey
		if recPubKey, err = loadPublicKey(recipientPubKeyPath); err != nil {
			return nil, err
		}
		if envelope.receiverKeys[iKey], err = rsa.EncryptPKCS1v15(rand.Reader, recPubKey, symKey); err != nil {
			return nil, err
		}
		if len(envelope.receiverKeys[iKey]) != KeySizeBit {
			return nil, fmt.Errorf("key size must be %d bits", KeySizeBit)
		}
	}
	return envelope.ToBytes(), nil
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
