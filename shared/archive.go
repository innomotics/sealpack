package shared

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
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
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
		receiverKey := bytes.NewBuffer([]byte{})
		if _, err = io.CopyN(receiverKey, rd, int64(k)*8); err != nil {
			return nil, err
		}
		envel.ReceiverKeys = append(envel.ReceiverKeys, receiverKey.Bytes())
	}
	if _, err = envel.PayloadReader.Seek(13, 0); err != nil {
		return nil, err
	}
	return envel, nil
}

// Envelope is the package with headers and so on
type Envelope struct {
	PayloadLen    int64
	PayloadReader io.ReadSeeker
	PayloadWriter *os.File
	HashAlgorithm crypto.Hash
	ReceiverKeys  [][]byte
}

// ToBytes provides an Envelope as Bytes.
// Caution: using this method may massively increase memory usage!
func (e *Envelope) ToBytes() []byte {
	// Add basic header information
	result := append(
		[]byte(EnvelopeMagicBytes),
		byte(e.HashAlgorithm),
	)
	// Payload Length
	payloadLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(payloadLen, uint64(e.PayloadLen))
	result = append(result, payloadLen...)
	// Then the Payload
	buf, _ := os.ReadFile(e.PayloadWriter.Name())
	result = append(result, buf...)
	// Finally, the receivers' keys prefixed with their digest sizes in bytes
	for _, key := range e.ReceiverKeys {
		result = append(result, uint8(len(key)/8))
		result = append(result, key...)
	}
	return result
}

// WriteHeader writes the envelope headers to an io.Writer.
func (e *Envelope) WriteHeader(w io.Writer) error {
	if _, err := w.Write([]byte(EnvelopeMagicBytes)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(e.HashAlgorithm)}); err != nil {
		return err
	}
	payloadLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(payloadLen, uint64(e.PayloadLen))
	if _, err := w.Write(payloadLen); err != nil {
		return err
	}
	return nil
}

// WriteKeys writes encrypted keys to an io.Writer.
func (e *Envelope) WriteKeys(w io.Writer) error {
	// Finally, the receivers' keys prefixed with their digest sizes in bytes
	for _, key := range e.ReceiverKeys {
		if _, err := w.Write([]byte{uint8(len(key) / 8)}); err != nil {
			return err
		}
		if _, err := w.Write(key); err != nil {
			return err
		}
	}
	return nil
}

// String prints a string representation of an Envelope with basic information
func (e *Envelope) String() string {
	sb := strings.Builder{}
	if len(e.ReceiverKeys) < 1 {
		sb.WriteString("File is a public package.\n")
	} else {
		sb.WriteString("File is a sealed package.\n")
	}
	sb.WriteString(fmt.Sprintf("\tPayload size (compressed): %d Bytes\n", e.PayloadLen))
	sb.WriteString(fmt.Sprintf("\tSingatures hashed using %s (%d Bit)\n", e.HashAlgorithm.String(), e.HashAlgorithm.Size()))
	if len(e.ReceiverKeys) > 0 {
		sb.WriteString(fmt.Sprintf("\tSealed for %d recievers\n", len(e.ReceiverKeys)))
	}
	return sb.String()
}

// WriteOutput creates an encrypted output file from encrypted payload
func (e *Envelope) WriteOutput(f *os.File, arc *WriteArchive) error {
	if err := e.WriteHeader(f); err != nil {
		return err
	}
	payload, err := os.Open(arc.outFile.Name())
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, payload); err != nil {
		return err
	}
	if err = payload.Close(); err != nil {
		return err
	}
	if err = e.WriteKeys(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

const (
	EnvelopeMagicBytes = "\xDBIPC" // ASCII sum of "ECS" = 333(octal) or DB(hex)
)

type WriteArchive struct {
	encryptWriter  io.WriteCloser
	compressWriter io.Writer
	tarWriter      *tar.Writer
	outFile        *os.File
	EncryptionKey  string
}

type ReadArchive struct {
	compressReader io.Reader
	TarReader      *tar.Reader
	reader         io.Reader
}

/**
 * TODO: Make compressWriter compression algorithm flexible
 */

// CreateArchiveWriter opens a stream of writers (tar to gzip to buffer) and funnel to a csutom writer.
func CreateArchiveWriter(public bool) *WriteArchive {
	f, err := os.CreateTemp("", "packed_contents")
	if err != nil {
		log.Fatal("could not create temp file")
	}
	arc := &WriteArchive{
		outFile: f,
	}
	if !public {
		arc.EncryptionKey, arc.encryptWriter = EncryptWriter(arc.outFile)
		arc.compressWriter = gzip.NewWriter(arc.encryptWriter)
	} else {
		arc.compressWriter = gzip.NewWriter(arc.outFile)
	}
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
// Additionally, it returns the size of the payload.
func (arc *WriteArchive) Finalize() (int64, error) {
	var err error
	// Finish archive packaging and get contents
	if err = arc.tarWriter.Close(); err != nil {
		return 0, err
	}
	_, closeable := arc.compressWriter.(interface{}).(io.Closer)
	if closeable {
		// Do not fail on closing closed closer
		if err = arc.compressWriter.(io.Closer).Close(); err != nil {
			return 0, err
		}
	}
	if arc.encryptWriter != nil {
		if err = arc.encryptWriter.Close(); err != nil {
			return 0, err
		}
	}
	// Collect size
	stat, err := os.Stat(arc.outFile.Name())
	if err != nil {
		return 0, err
	}
	return stat.Size(), nil
}

func (arc *WriteArchive) Cleanup() error {
	// Close if not already done
	_ = arc.outFile.Close()
	return os.Remove(arc.outFile.Name())
}

// WriteToArchive adds a new file identified by its name to the tar.gz archive.
// The contents are added as reader resource.
func (arc *WriteArchive) WriteToArchive(fileName string, contents *os.File) error {
	info, err := contents.Stat()
	if err != nil {
		return err
	}
	if err = arc.tarWriter.WriteHeader(&tar.Header{
		Name:    fileName,
		Size:    info.Size(),
		Mode:    0755,
		ModTime: time.Now(),
	}); err != nil {
		return err
	}
	if _, err = contents.Seek(0, 0); err != nil {
		return err
	}
	_, err = io.CopyN(arc.tarWriter, contents, info.Size())
	if err != nil {
		return err
	}
	return arc.tarWriter.Flush()
}

// AddToArchive adds a new file identified by its name to the tar.gz archive.
// The contents are added as byte slices.
func (arc *WriteArchive) AddToArchive(imgName string, contents []byte) error {
	return BytesToTar(arc.tarWriter, &imgName, contents)
}

// BytesToTar adds a file to a writer using a filename and a byte slice with contents to be written.
func BytesToTar(w *tar.Writer, filename *string, contents []byte) error {
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
