package common

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
	"crypto"
	"encoding/binary"
	"fmt"
	"github.com/apex/log"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/ovh/symmecrypt"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// EnvelopeMagicBytes is set to ASCII sum of "ECS" = 333(octal) or DB(hex)
	EnvelopeMagicBytes = "\xDBIPC"
	TocFileName        = ".sealpack.toc"
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
	// config Contains 2 infos (LSB)
	// Bytes 7-5: Compression algorithm
	// Bytes 4-0: Hash algorithm
	config, err := rd.ReadByte()
	if err != nil {
		return nil, err
	}
	envel := &Envelope{
		HashAlgorithm:   crypto.Hash(config & 0b00011111),
		CompressionAlgo: config >> 5,
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
	// 4 Magic Bytes + 1 Byte Hash Algorithm + 8 Bytes Payload Length = 13 Bytes offset
	if _, err = envel.PayloadReader.Seek(13, 0); err != nil {
		return nil, err
	}
	return envel, nil
}

// Envelope is the package with headers and so on
type Envelope struct {
	PayloadLen      int64
	PayloadReader   io.ReadSeeker
	PayloadWriter   *os.File
	HashAlgorithm   crypto.Hash
	CompressionAlgo uint8
	ReceiverKeys    [][]byte
}

// ToBytes provides an Envelope as Bytes.
// Caution: using this method may massively increase memory usage!
func (e *Envelope) ToBytes() []byte {
	// Add basic header information
	result := append(
		[]byte(EnvelopeMagicBytes),
		(e.CompressionAlgo<<5)|uint8(e.HashAlgorithm),
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
	if _, err := w.Write([]byte{(e.CompressionAlgo << 5) | uint8(e.HashAlgorithm)}); err != nil {
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
		if len(key)%8 != 0 {
			return fmt.Errorf("invalid key length")
		}
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
	sb.WriteString(fmt.Sprintf("\tSignatures hashed using %s (%d Bit)\n", e.HashAlgorithm.String(), e.HashAlgorithm.Size()))
	if len(e.ReceiverKeys) > 0 {
		sb.WriteString(fmt.Sprintf("\tSealed for %d receivers\n", len(e.ReceiverKeys)))
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

// GetPayload provides the Payload from the envelope
func (e *Envelope) GetPayload() (payload io.Reader, err error) {
	if len(e.ReceiverKeys) < 1 {
		log.Info("unseal: read public archive")
		// Was not encrypted: public archive
		payload = e.PayloadReader
	} else {
		log.Infof("unseal: read archive sealed for %d receivers", len(e.ReceiverKeys))
		// Try to find a key that can be decrypted with the provided private key
		var pKey PrivateKey
		pKey, err = LoadPrivateKey(Unseal.PrivKeyPath)
		if err != nil {
			return
		}
		var symKey symmecrypt.Key
		for _, key := range e.ReceiverKeys {
			symKey, err = TryUnsealKey(key, pKey)
			if err == nil {
				break
			}
		}
		if symKey == nil {
			return nil, fmt.Errorf("not sealed for the provided private key")
		}
		// Decrypt the payload and decrypt it
		payload, err = symmecrypt.NewReader(io.LimitReader(e.PayloadReader, e.PayloadLen), symKey)
	}
	return
}

/****************
 * WriteArchive *
 ****************/

type WriteArchive struct {
	encryptWriter   io.WriteCloser
	compressWriter  io.WriteCloser
	compressionAlgo uint8
	tarWriter       *tar.Writer
	outFile         *os.File
	EncryptionKey   string
}

const (
	CompressionGzip  = "gzip"
	CompressionZlib  = "zlib"
	CompressionZip   = "zip"
	CompressionFlate = "flate"
)

// compressionAlgorithms as provided by https://github.com/klauspost/compress/
var compressionAlgorithms = []string{
	CompressionGzip,
	CompressionZlib,
	CompressionZip,
	CompressionFlate,
}

// GetCompressionAlgoName gets the name of an algo index or defaults to gzip (0)
func GetCompressionAlgoName(idx uint8) string {
	if idx >= uint8(len(compressionAlgorithms)) {
		log.Warnf("Invalid algorithm index '%d', defaulting to '%s'", idx, compressionAlgorithms[0])
		idx = 0
	}
	return compressionAlgorithms[idx]
}

// GetCompressionAlgoIndex gets the index of an algo name or defaults to 0 (gzip)
func GetCompressionAlgoIndex(algo string) uint8 {
	for i, algoName := range compressionAlgorithms {
		if algoName == algo {
			return uint8(i)
		}
	}
	log.Warnf("Invalid algorithm '%s', defaulting to '%s'", algo, compressionAlgorithms[0])
	return 0
}

// CreateArchiveWriter opens a stream of writers (tar to gzip to buffer) and funnel to a csutom writer.
func CreateArchiveWriter(public bool, compressionAlgo uint8) *WriteArchive {
	f, err := os.CreateTemp("", "packed_contents")
	if err != nil {
		log.Fatal("could not create temp file")
	}
	arc := &WriteArchive{
		outFile: f,
	}
	if !public {
		arc.EncryptionKey, arc.encryptWriter = EncryptWriter(arc.outFile)
		arc.InitializeCompression(arc.encryptWriter, compressionAlgo)
	} else {
		arc.InitializeCompression(arc.outFile, compressionAlgo)
	}
	arc.tarWriter = tar.NewWriter(arc.compressWriter)
	return arc
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

// Cleanup closes streams and removes temporary files
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

// AddContents adds first files, secondly images to the WriteArchive providing FileSignatures for verification
func (arc *WriteArchive) AddContents(signatures *FileSignatures) (err error) {
	err = arc.addFiles(signatures)
	if err != nil {
		return
	}
	err = arc.addImages(signatures)
	return
}

// addImages adds images to the WriteArchive providing FileSignatures for verification
func (arc *WriteArchive) addImages(signatures *FileSignatures) (err error) {
	var inFile *os.File
	for _, content := range Seal.Images {
		inFile, err = SaveImage(content)
		if err != nil {
			return fmt.Errorf("failed reading image: %v", err)
		}
		if err = arc.storeContents(inFile, content.ToFileName(), signatures); err != nil {
			return
		}
	}
	return
}

// addFiles adds files to the WriteArchive providing FileSignatures for verification
func (arc *WriteArchive) addFiles(signatures *FileSignatures) (err error) {
	var globs []string
	var inFile *os.File
	for _, glob := range Seal.Files {
		globs, err = filepath.Glob(glob)
		if err != nil {
			return fmt.Errorf("invalid file glob: %v", err)
		}
		for _, content := range globs {
			inFile, err = os.Open(content)
			content = strings.TrimPrefix(content, "/")
			if err != nil {
				return fmt.Errorf("failed reading file: %v", err)
			}
			if err = arc.storeContents(inFile, content, signatures); err != nil {
				return
			}
		}
	}
	return
}

// storeContents adds an io.Reader and a filename to add a signature and the contents to the archive.
func (arc *WriteArchive) storeContents(inFile *os.File, filename string, signatures *FileSignatures) error {
	var err error
	if _, err = inFile.Seek(0, 0); err != nil {
		return err
	}
	if err = signatures.AddFileFromReader(filename, inFile); err != nil {
		return fmt.Errorf("failed hashing image: %v", err)
	}
	if err = arc.WriteToArchive(filename, inFile); err != nil {
		return fmt.Errorf("failed adding image to archive: %v", err)
	}
	if err = inFile.Close(); err != nil {
		return err
	}
	return nil
}

// AddToc adds signatures to the archive
func (arc *WriteArchive) AddToc(signatures *FileSignatures) (err error) {
	// Create Signer according to configuration
	var signer signature.Signer
	signer, err = CreateSigner()
	if err != nil {
		return fmt.Errorf("seal: could not create signer: %v", err)
	}
	if err = arc.AddToArchive(TocFileName, signatures.Bytes()); err != nil {
		return fmt.Errorf("seal: failed adding TOC to archive: %v", err)
	}
	reader := bytes.NewReader(signatures.Bytes())
	tocSignature, err := signer.SignMessage(reader, options.NoOpOptionImpl{})
	if err != nil {
		return fmt.Errorf("seal: failed signing TOC: %v", err)
	}
	if err = arc.AddToArchive(TocFileName+".sig", tocSignature); err != nil {
		return fmt.Errorf("seal: failed adding TOC signature to archive: %v", err)
	}
	return
}

// InitializeCompression creates a compression writer based on selected algorithm
func (arc *WriteArchive) InitializeCompression(w io.WriteCloser, compressionAlgo uint8) {
	switch compressionAlgo {
	case 1: // zlib
		arc.compressWriter = zlib.NewWriter(w)
		break
	case 2: // zip
		log.Warnf("ZIP writer currently not implemented")
		arc.compressWriter = w
		break
	case 3: // flate
		arc.compressWriter, _ = flate.NewWriter(w, flate.DefaultCompression)
		break
	default: // gzip
		arc.compressWriter = gzip.NewWriter(w)
		break
	}
}

/***************
 * ReadArchive *
 ***************/

type ReadArchive struct {
	compressReader io.Reader
	TarReader      *tar.Reader
	reader         io.Reader
}

// OpenArchive opens a compressed tar archive for reading
func OpenArchive(data []byte, compressionAlgo uint8) (arc *ReadArchive, err error) {
	arc = &ReadArchive{
		reader: bytes.NewReader(data),
	}
	err = arc.InitializeCompression(arc.reader, compressionAlgo)
	if err != nil {
		return nil, err
	}
	arc.TarReader = tar.NewReader(arc.compressReader)
	return arc, nil
}

// OpenArchiveReader opens a compressed tar archive for reading from a reader
func OpenArchiveReader(r io.Reader, compressionAlgo uint8) (arc *ReadArchive, err error) {
	arc = &ReadArchive{
		reader: r,
	}
	err = arc.InitializeCompression(arc.reader, compressionAlgo)
	if err != nil {
		return nil, err
	}
	arc.TarReader = tar.NewReader(arc.compressReader)
	return arc, nil
}

func (arc *ReadArchive) Unpack() (err error) {
	var h *tar.Header
	log.Debug("unseal: create verifier")
	verifier, err := NewVerifier()
	if err != nil {
		return err
	}
	for {
		h, err = arc.TarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeReg:
			if err = arc.extract(h, verifier); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown type: %b in %s", h.Typeflag, h.Name)
		}
	}
	log.Debug("unseal: verifying contents signature")
	return verifier.Verify()
}

func (arc *ReadArchive) extract(h *tar.Header, v *Verifier) (err error) {
	fullFile := filepath.Join(Unseal.OutputPath, h.Name)
	if !strings.HasPrefix(h.Name, ContainerImagePrefix) { // Skip creation of folder for images
		if err = os.MkdirAll(filepath.Dir(fullFile), 0755); err != nil {
			return fmt.Errorf("creating archive for %s failed: %s", fullFile, err.Error())
		}
	}
	if !strings.HasPrefix(h.Name, TocFileName) {
		err = arc.extractContentFile(h, fullFile, v)
	} else {
		err = v.AddTocComponent(h, arc.TarReader)
	}
	return err
}

// extractContentFile reads a single file from sealed archive and stores as local file or container image
func (arc *ReadArchive) extractContentFile(h *tar.Header, fullFile string, verify *Verifier) (err error) {
	// Use pipe to parallel read body and create signature
	buf, bufW := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		reader := io.TeeReader(arc.TarReader, bufW)
		// If file: persist, if image: import
		if strings.HasPrefix(h.Name, ContainerImagePrefix) {
			err = arc.storeImage(h, reader, verify)
			if err != nil {
				errCh <- err
			}
		} else {
			if err = arc.storeFile(h, reader, fullFile); err != nil {
				errCh <- err
			}
		}
		defer func() {
			errCh <- bufW.Close()
		}()
	}()
	if err = verify.Signatures.AddFileFromReader(h.Name, buf); err != nil {
		return
	}
	err = <-errCh
	return
}

// storeFile creates a file with a specified name and copies contents from a Reader to it
func (arc *ReadArchive) storeFile(h *tar.Header, r io.Reader, fullFile string) (err error) {
	f, err := os.Create(fullFile)
	if err != nil {
		return err
	}
	if bts, err := io.Copy(f, r); err != nil {
		log.Errorf("unseal: EOF after %d bytes of %d\n", bts, h.Size)
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return nil
}

// storeImage imports a binary image from a Reader into a registry specified by a Tag
func (arc *ReadArchive) storeImage(h *tar.Header, r io.Reader, v *Verifier) (err error) {
	var tag name.Tag
	if tag, err = name.NewTag(strings.TrimPrefix(h.Name, ContainerImagePrefix+"/")); err != nil {
		return err
	}
	// If everything matches, reimport images if target registry has been provided
	var wasImported bool
	if wasImported, err = ImportImage(io.NopCloser(r), &tag); wasImported {
		v.AddUnsafeTag(&tag)
		return nil
	}
	return err
}

// InitializeCompression creates a compression writer based on selected algorithm
func (arc *ReadArchive) InitializeCompression(r io.Reader, compressionAlgo uint8) (err error) {
	switch compressionAlgo {
	case 1: // zlib
		arc.compressReader, err = zlib.NewReader(r)
		break
	case 2: // zip
		log.Warnf("ZIP writer currently not implemented")
		arc.compressReader = r
		break
	case 3: // flate
		arc.compressReader = flate.NewReader(r)
		break
	default: // gzip
		arc.compressReader, err = gzip.NewReader(r)
		break
	}
	return
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
