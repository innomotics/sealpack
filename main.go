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
	appConfig []common.PackageContent
	signer    signature.Signer
)

// main is the central entrypoint for sealpack.
func main() {

	// Parse CLI params and config
	check(ParseCommands())
}

func sealCommand() error {
	var err error

	// 1. Create Signer according to configuration
	_, _ = fmt.Fprintln(os.Stderr, "[1] Create Signer")
	signer, err = common.CreateSigner()
	check(err)

	// 2. Prepare TARget (pun intended) and add files and signatures
	_, _ = fmt.Fprintln(os.Stderr, "[2] Bundling WriteArchive")
	arc := shared.CreateArchive()
	signatures := common.NewSignatureList(common.Seal.HashingAlgorithm)
	var body []byte
	for _, content := range common.Seal.Files {
		body, err = os.ReadFile(content)
		content = strings.TrimPrefix(content, "/")
		if err != nil {
			return fmt.Errorf("failed reading file: %v", err)
		}
		if err = signatures.AddFile(content, body); err != nil {
			return fmt.Errorf("failed hashing file: %v", err)
		}
		if err = arc.AddToArchive(content, body); err != nil {
			return fmt.Errorf("failed adding file to archive: %v", err)
		}
	}
	for _, content := range common.Seal.Images {
		body, err = common.SaveImage(&content)
		if err != nil {
			return fmt.Errorf("failed reading image: %v", err)
		}
		if err = signatures.AddFile(content.ToFileName(), body); err != nil {
			return fmt.Errorf("failed hashing image: %v", err)
		}
		if err = arc.AddToArchive(content.ToFileName(), body); err != nil {
			return fmt.Errorf("failed adding image to archive: %v", err)
		}
	}

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

	// 4. Encrypt archive
	_, _ = fmt.Fprintln(os.Stderr, "[4] Encrypting WriteArchive")
	archive, err := arc.Finalize()
	if err != nil {
		return fmt.Errorf("failed encrypting archive: %v", err)
	}
	// Now create encryption key and seal them for all recipients
	envelope := shared.Envelope{
		HashAlgorithm: common.GetConfiguredHashAlgorithm(common.Seal.HashingAlgorithm),
	}
	if common.Seal.Public {
		envelope.ReceiverKeys = [][]byte{}
		envelope.PayloadEncrypted = archive
	} else {
		var symKey []byte
		if envelope.PayloadEncrypted, symKey, err = common.Encrypt(archive); err != nil {
			return err
		}
		envelope.ReceiverKeys = make([][]byte, len(common.Seal.RecipientPubKeyPaths))
		for iKey, recipientPubKeyPath := range common.Seal.RecipientPubKeyPaths {
			var recPubKey *rsa.PublicKey
			if recPubKey, err = common.LoadPublicKey(recipientPubKeyPath); err != nil {
				return err
			}
			if envelope.ReceiverKeys[iKey], err = rsa.EncryptPKCS1v15(rand.Reader, recPubKey, symKey); err != nil {
				return err
			}
			if len(envelope.ReceiverKeys[iKey]) != recPubKey.Size() {
				return fmt.Errorf("key size must be %d bits", recPubKey.Size())
			}
		}
	}
	// 5. Store encrypted file
	_, _ = fmt.Fprintln(os.Stderr, "[5] Save WriteArchive")
	return common.WriteFile(envelope.ToBytes())
}

func inspectCommand() error {
	raw, err := os.ReadFile(common.SealedFile)
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

func unsealCommand() error {
	verifier, err := common.CreatePKIVerifier()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(common.SealedFile)
	if err != nil {
		return err
	}
	// Try to parse the envelope
	envelope, err := shared.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	var payload []byte
	if len(envelope.ReceiverKeys) < 1 {
		// Was not encrypted: public archive
		payload = envelope.PayloadEncrypted
	} else {
		// Try to find a key that can be decrypted with the provided private key
		pKey, err := common.LoadPrivateKey(common.Unseal.PrivKeyPath)
		if err != nil {
			return err
		}
		var symKey symmecrypt.Key
		for _, key := range envelope.ReceiverKeys {
			symKey, err = common.TryUnsealKey(key, pKey)
			if err == nil {
				break
			}
			fmt.Println(err)
		}
		if symKey == nil {
			return fmt.Errorf("not sealed for the provided private key")
		}
		// Decrypt the payload and decrypt it
		payload, err = symKey.Decrypt(envelope.PayloadEncrypted)
		if err != nil {
			return err
		}
	}
	archive, err := shared.OpenArchive(payload)
	if err != nil {
		return err
	}
	var h *tar.Header
	signatures := common.NewSignatureList(common.Unseal.HashingAlgorithm)
	var toc, tocSignature []byte
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
			outFile := new(bytes.Buffer)
			if _, err = io.Copy(outFile, archive.TarReader); err != nil {
				log.Fatalf("read contents failed: %s", err.Error())
			}
			if !strings.HasPrefix(h.Name, TocFileName) {
				if err = signatures.AddFile(h.Name, outFile.Bytes()); err != nil {
					return err
				}
				if err = os.WriteFile(fullFile, outFile.Bytes(), 0755); err != nil {
					return err
				}
			} else {
				if h.Name == TocFileName {
					toc = outFile.Bytes()
				} else {
					tocSignature = outFile.Bytes()
				}
			}
		default:
			return fmt.Errorf("unknown type: %s in %s", h.Typeflag, h.Name)
		}
	}
	// Test if TOC matches collected signatures TOC amd then verify that the TOC signature matches the binary TOC
	if bytes.Compare(toc, signatures.Bytes()) != 0 {
		return fmt.Errorf("tocs not matching")
	}
	if err = verifier.VerifySignature(bytes.NewReader(tocSignature), bytes.NewReader(toc)); err != nil {
		return err
	}

	// If everything matches, reimport images if target registry has been provided
	if common.Unseal.TargetRegistry != "" {
		if err = common.ImportImages(); err != nil {
			return err
		}
	}
	return nil
}

// check tests if an error is nil; if not, it logs the error and exits the program
func check(err error, plus ...string) {
	if err != nil {
		log.Fatalln(err, plus)
	}
}
