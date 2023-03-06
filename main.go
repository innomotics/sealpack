package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/ovh/symmecrypt"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"io"
	"log"
	"os"
	"path/filepath"
	"sealpack/common"
	"sealpack/shared"
	"strings"
)

const (
	TocFileName = ".sealpack.toc"
)

var (
	signer signature.Signer
)

// main is the central entrypoint for sealpack.
func main() {
	// Parse CLI params and config
	check(ParseCommands())
}

// sealCommand is the combined command for sealing
func sealCommand() error {
	var err error
	// 1. Create Signer according to configuration
	_, _ = fmt.Fprintln(os.Stderr, "[1] Create Signer")
	signer, err = common.CreateSigner()
	check(err)

	// 1.1 Create envelope for the resulting file
	envelope := shared.Envelope{
		HashAlgorithm: common.GetHashAlgorithm(common.Seal.HashingAlgorithm),
	}

	// 2. Prepare TARget (pun intended) and add files and signatures
	_, _ = fmt.Fprintln(os.Stderr, "[2] Bundling WriteArchive")
	arc := shared.CreateArchiveWriter(common.Seal.Public)
	signatures := common.NewSignatureList(common.Seal.HashingAlgorithm)
	if err = addContents(signatures, arc); err != nil {
		return err
	}
	_ = common.CleanupImages() // Ignore: may not exist if no images have been stored

	// 3. Add TOC and sign it
	_, _ = fmt.Fprintln(os.Stderr, "[3] Adding TOC")
	if err = arc.AddToArchive(TocFileName, signatures.Bytes()); err != nil {
		return fmt.Errorf("failed adding TOC to archive: %v", err)
	}
	reader := bytes.NewReader(signatures.Bytes())
	tocSignature, err := signer.SignMessage(reader, options.NoOpOptionImpl{})
	if err != nil {
		return fmt.Errorf("failed signing TOC: %v", err)
	}
	if err = arc.AddToArchive(TocFileName+".sig", tocSignature); err != nil {
		return fmt.Errorf("failed adding TOC signature to archive: %v", err)
	}
	envelope.PayloadLen, err = arc.Finalize()
	if err != nil {
		return fmt.Errorf("failed finalizing archive: %v", err)
	}

	// 4. Encrypt keys
	_, _ = fmt.Fprintln(os.Stderr, "[4] Encrypting WriteArchive")
	// Now create encryption key and seal them for all recipients
	if err = addKeys(envelope, []byte(arc.EncryptionKey)); err != nil {
		return err
	}

	// 5. Write envelope
	out, err := common.NewOutputFile()
	if err != nil {
		return err
	}
	if err = envelope.WriteOutput(out, arc); err != nil {
		return err
	}
	if err = arc.Cleanup(); err != nil {
		return err
	}
	if err = common.CleanupFileWriter(out); err != nil {
		return err
	}
	return nil
}

// addKeys encrypts the symmetric key for every receiver and attaches them to the envelope
func addKeys(envelope shared.Envelope, plainKey []byte) error {
	var err error
	envelope.ReceiverKeys = [][]byte{}
	if !common.Seal.Public {
		envelope.ReceiverKeys = make([][]byte, len(common.Seal.RecipientPubKeyPaths))
		for iKey, recipientPubKeyPath := range common.Seal.RecipientPubKeyPaths {
			var recPubKey *rsa.PublicKey
			if recPubKey, err = shared.LoadPublicKey(recipientPubKeyPath); err != nil {
				return err
			}
			if envelope.ReceiverKeys[iKey], err = rsa.EncryptPKCS1v15(rand.Reader, recPubKey, plainKey); err != nil {
				return err
			}
			if len(envelope.ReceiverKeys[iKey]) != recPubKey.Size() {
				return fmt.Errorf("key size must be %d bits", recPubKey.Size())
			}
		}
	}
	return nil
}

// addContents adds all requested files and images to the archive
func addContents(signatures *common.FileSignatures, arc *shared.WriteArchive) error {
	var inFile *os.File
	var globs []string
	var err error
	for _, glob := range common.Seal.Files {
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
			if err = storeContents(inFile, content, signatures, arc); err != nil {
				return err
			}
		}
	}
	for _, content := range common.Seal.Images {
		inFile, err = common.SaveImage(content)
		if err != nil {
			return fmt.Errorf("failed reading image: %v", err)
		}
		if err = storeContents(inFile, content.ToFileName(), signatures, arc); err != nil {
			return err
		}
	}
	return nil
}

// storeContents adds an io.Reader and a filename to add a signature and the contents to the archive.
func storeContents(inFile *os.File, filename string, signatures *common.FileSignatures, arc *shared.WriteArchive) error {
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

// inspectCommand is the central command for inspecting a potentially sealed file
func inspectCommand() error {
	raw, err := os.Open(common.SealedFile)
	if err != nil {
		return err
	}
	envelope, err := shared.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	fmt.Println(envelope.String())
	return nil
}

// unsealCommand is the combined command for unsealing
func unsealCommand() error {
	verifier, err := shared.CreatePKIVerifier(common.Unseal.SigningKeyPath)
	if err != nil {
		return err
	}
	raw, err := os.Open(common.SealedFile)
	if err != nil {
		return err
	}
	// Try to parse the envelope
	envelope, err := shared.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	var payload io.Reader
	if len(envelope.ReceiverKeys) < 1 {
		// Was not encrypted: public archive
		payload = envelope.PayloadReader
	} else {
		// Try to find a key that can be decrypted with the provided private key
		pKey, err := shared.LoadPrivateKey(common.Unseal.PrivKeyPath)
		if err != nil {
			return err
		}
		var symKey symmecrypt.Key
		for _, key := range envelope.ReceiverKeys {
			symKey, err = shared.TryUnsealKey(key, pKey)
			if err == nil {
				break
			}
		}
		if symKey == nil {
			return fmt.Errorf("not sealed for the provided private key")
		}
		// Decrypt the payload and decrypt it
		payload, err = symmecrypt.NewReader(io.LimitReader(envelope.PayloadReader, envelope.PayloadLen), symKey)
		if err != nil {
			return err
		}
	}
	archive, err := shared.OpenArchiveReader(payload)
	if err != nil {
		return err
	}
	var h *tar.Header
	signatures := common.NewSignatureList(common.Unseal.HashingAlgorithm)
	var toc, tocSignature *bytes.Buffer
	for {
		h, err = archive.TarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(filepath.Join(common.Unseal.OutputPath, h.Name), 0755); err != nil {
				return fmt.Errorf("creating archive %s failed: %s", h.Name, err.Error())
			}
		case tar.TypeReg:
			fullFile := filepath.Join(common.Unseal.OutputPath, h.Name)
			if err = os.MkdirAll(filepath.Dir(fullFile), 0755); err != nil {
				return fmt.Errorf("creating archive for %s failed: %s", fullFile, err.Error())
			}
			if !strings.HasPrefix(h.Name, TocFileName) {
				// Use pipe to parallel read body and create signature
				buf, bufW := io.Pipe()
				errCh := make(chan error, 1)
				go func() {
					reader := io.TeeReader(archive.TarReader, bufW)
					f, err := os.Create(fullFile)
					if err != nil {
						errCh <- err
					}
					if bts, err := io.Copy(f, reader); err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "EOF after %d bytes of %d\n", bts, h.Size)
						errCh <- err
					}
					if err = f.Sync(); err != nil {
						errCh <- err
					}
					if err = f.Close(); err != nil {
						errCh <- err
					}
					defer func() {
						errCh <- bufW.Close()
					}()
				}()
				if err = signatures.AddFileFromReader(h.Name, buf); err != nil {
					return err
				}
				if err = <-errCh; err != nil && err != io.EOF {
					return err
				}
			} else {
				if h.Name == TocFileName {
					toc = new(bytes.Buffer)
					if _, err = io.Copy(toc, archive.TarReader); err != nil {
						return err
					}
				} else {
					tocSignature = new(bytes.Buffer)
					if _, err = io.Copy(tocSignature, archive.TarReader); err != nil {
						return err
					}
				}
			}
		default:
			return fmt.Errorf("unknown type: %b in %s", h.Typeflag, h.Name)
		}
	}
	// Test if TOC matches collected signatures TOC amd then verify that the TOC signature matches the binary TOC
	if bytes.Compare(toc.Bytes(), signatures.Bytes()) != 0 {
		return fmt.Errorf("tocs not matching")
	}
	if err = verifier.VerifySignature(tocSignature, toc); err != nil {
		return err
	}

	// If everything matches, reimport images if target registry has been provided
	return common.ImportImages()
}

// check tests if an error is nil; if not, it logs the error and exits the program
func check(err error, plus ...string) {
	if err != nil {
		log.Fatalln(err, plus)
	}
}
