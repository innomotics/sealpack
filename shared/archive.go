package shared

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

// ParseEnvelope tries to extract the information for an Envelope from a byte slice
func ParseEnvelope(input io.ReadSeeker) (*Envelope, error) {
	rd := bufio.NewReader(input)
	sig, err := rd.Peek(len(EnvelopeMagicBytes))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sig, []byte(EnvelopeMagicBytes)) {
		return nil, fmt.Errorf("not a valid sealpack file")
	}
	if _, err = rd.Discard(len(EnvelopeMagicBytes)); err != nil {
		return nil, err
	}
	algoCode, err := rd.ReadByte()
	if err != nil {
		return nil, err
	}
	envel := &Envelope{
		HashAlgorithm: crypto.Hash(algoCode),
	}
	payload := make([]byte, 8)
	if _, err = rd.Read(payload); err != nil {
		return nil, err
	}
	envel.PayloadLen = int64(binary.LittleEndian.Uint64(payload))
	envel.PayloadReader = input
	if _, err = rd.Discard(int(envel.PayloadLen)); err != nil {
		return nil, err
	}
	var k byte
	for {
		k, err = rd.ReadByte()
		if err != nil {
			break
		}
		receiverKey := make([]byte, int(k)*8)
		if _, err = rd.Read(receiverKey); err != nil {
			return nil, err
		}
		envel.ReceiverKeys = append(envel.ReceiverKeys, receiverKey)
	}
	envel.PayloadReader.Seek(13, 0)
	return envel, nil
}

// Envelope is the package with headers and so on
type Envelope struct {
	PayloadLen       int64
	PayloadReader    io.ReadSeeker
	PayloadEncrypted []byte
	HashAlgorithm    crypto.Hash
	ReceiverKeys     [][]byte
}

// ToBytes provides an Envelope as Bytes
func (e *Envelope) ToBytes() []byte {
	result := append(
		[]byte(EnvelopeMagicBytes),
		byte(e.HashAlgorithm),
	)
	// Payload Length
	payloadLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(payloadLen, uint64(len(e.PayloadEncrypted)))
	result = append(result, payloadLen...)
	// Then the Payload
	result = append(result, e.PayloadEncrypted...)
	// Finally, the receivers' keys prefixed with their digest sizes in bytes
	for _, key := range e.ReceiverKeys {
		result = append(result, uint8(len(key)/8))
		result = append(result, key...)
	}
	return result
}

// String prints a string representation of an Envelope with basic information
func (e *Envelope) String() string {
	sb := strings.Builder{}
	if len(e.ReceiverKeys) < 1 {
		sb.WriteString("File is a public package.\n")
	} else {
		sb.WriteString("File is a sealed package.\n")
	}
	if len(e.PayloadEncrypted) > 0 && e.PayloadLen == 0 {
		e.PayloadLen = int64(len(e.PayloadEncrypted))
	}
	sb.WriteString(fmt.Sprintf("\tPayload size (compressed): %d Bytes\n", e.PayloadLen))
	sb.WriteString(fmt.Sprintf("\tSingatures hashed using %s (%d Bit)\n", e.HashAlgorithm.String(), e.HashAlgorithm.Size()))
	if len(e.ReceiverKeys) > 0 {
		sb.WriteString(fmt.Sprintf("\tSealed for %d recievers\n", len(e.ReceiverKeys)))
	}
	return sb.String()
}

const (
	EnvelopeMagicBytes = "\xDBIPC" // ASCII sum of "ECS" = 333(octal) or DB(hex)
)

type WriteArchive struct {
	compressWriter io.Writer
	tarWriter      *tar.Writer
	buffer         *bytes.Buffer
}

type ReadArchive struct {
	compressReader io.Reader
	TarReader      *tar.Reader
	reader         io.Reader
}

/**
 * TODO: Make compressWriter compression algorithm flexible
 */

// CreateArchive opens a stream of writers (tar to gzip to buffer).
// Bytes added to the stream will be added to the tar.gz archive.
// It can be retrieved through the buffer as byte slice.
func CreateArchive() *WriteArchive {
	arc := &WriteArchive{
		buffer: new(bytes.Buffer),
	}
	arc.compressWriter = gzip.NewWriter(arc.buffer)
	arc.tarWriter = tar.NewWriter(arc.compressWriter)
	return arc
}

// OpenArchive opens a compressed tar archive for reading
func OpenArchive(data []byte) (arc *ReadArchive, err error) {
	arc = &ReadArchive{
		reader: bytes.NewReader(data),
	}
	arc.compressReader, err = gzip.NewReader(arc.reader)
	if err != nil {
		return nil, err
	}
	arc.TarReader = tar.NewReader(arc.compressReader)
	return arc, nil
}

// OpenArchiveReader opens a compressed tar archive for reading from a reader
func OpenArchiveReader(r io.Reader) (arc *ReadArchive, err error) {
	arc = &ReadArchive{
		reader: r,
	}
	arc.compressReader, err = gzip.NewReader(arc.reader)
	if err != nil {
		return nil, err
	}
	arc.TarReader = tar.NewReader(arc.compressReader)
	return arc, nil
}

// Finalize closes the tar and gzip writers and retrieves the archive.
// In addition
func (arc *WriteArchive) Finalize() ([]byte, error) {
	// Finish archive packaging and get contents
	var err error
	_, closeable := arc.compressWriter.(interface{}).(io.Closer)
	if closeable {
		_ = arc.compressWriter.(io.Closer).Close()
	}
	_ = arc.tarWriter.Close()
	return arc.buffer.Bytes(), err
}

// AddToArchive adds a new file identified by its name to the tar.gz archive.
// The contents are added as byte slices.
func (arc *WriteArchive) AddToArchive(imgName string, contents []byte) error {
	return WriteToTar(arc.tarWriter, &imgName, contents)
}

// WriteToTar adds a file to a writer using a filename and a byte slice with contents to be written.
func WriteToTar(w *tar.Writer, filename *string, contents []byte) error {
	var err error
	if err = w.WriteHeader(&tar.Header{
		Name:    *filename,
		Size:    int64(len(contents)),
		Mode:    0755,
		ModTime: time.Now(),
	}); err != nil {
		return err
	}
	_, err = w.Write(contents)
	if err != nil {
		return err
	}
	return w.Flush()
}
