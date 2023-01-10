package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/sigstore/sigstore/pkg/signature"
	"log"
	"os"
	"sealpack/common"
)

const (
	UpgradeFilenameSuffix    = "ipc"
	TocFileName              = ".sealpack.toc"
	ApplicationConfigPattern = "application.v*.json"
)

var (
	appConfig []common.PackageContent
	signer    signature.Signer
)

// main is the central entrypoint for sealpack.
func main() {

	// Parse CLI params and config
	check(common.ParseCommands())

	if common.IsSealCmd() {
		check(sealCommand())
	}
}

func sealCommand() error {
	var err error

	// 1. Create Signer according to configuration
	fmt.Println("[1] Create Signer")
	signer, err = common.CreateSigner()
	check(err)

	// 2. Prepare TARget (pun intended) and add files and signatures
	fmt.Println("[2] Bundling Archive")
	arc := common.CreateArchive()
	signatures := common.NewSignatureList()
	var body []byte
	for _, content := range common.Seal.Files {
		body, err = os.ReadFile(content)
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
	fmt.Println("[3] Adding TOC")
	if err = arc.AddToArchive(TocFileName, signatures.Bytes()); err != nil {
		return fmt.Errorf("failed adding TOC to archive: %v", err)
	}
	tocSignature, err := signer.SignMessage(bytes.NewReader(signatures.Bytes()), nil)
	if err != nil {
		return fmt.Errorf("failed signing TOC: %v", err)
	}
	if err = arc.AddToArchive(TocFileName, tocSignature); err != nil {
		return fmt.Errorf("failed adding TOC signature to archive: %v", err)
	}

	// 4. Encrypt archive
	fmt.Println("[4] Encrypting Archive")
	archive, err := arc.Finalize()
	if err != nil {
		return fmt.Errorf("failed encrypting archive: %v", err)
	}

	// 5. Move encrypted file to S3
	fmt.Println("[5] Uploading Archive")
	ipcFileName := params.GetPackageName(UpgradeFilenameSuffix)
	err = aws2.s3UploadArchive(archive, ipcFileName)
	if err != nil {
		return "failed uploading to S3", err
	}

	// 6. Create preshared key and return its url
	fmt.Println("[6] Create Presigned Link")
	urlStr, err := aws2.s3CreatePresignedDownload(ipcFileName)
	if err != nil {
		return "failed presigning", err
	}
	return urlStr, nil
}

// encryptArchive applies an AES GCM encryption on a file represented as a byte slice.
// The result is an encrypted file, represented again as a byte slice.
func encryptArchive(body []byte) ([]byte, error) {
	aesKey, err := aws2.getEncryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	return aesGCM.Seal(nil, nonce, body, nil), nil
}

func check(err error, plus ...string) {
	if err != nil {
		log.Fatalln(err, plus)
	}
}
