package main

import (
	"bytes"
	"fmt"
	"github.com/sigstore/sigstore/pkg/signature"
	"log"
	"os"
	"sealpack/common"
)

const (
	UpgradeFilenameSuffix = "ipc"
	TocFileName           = ".sealpack.toc"
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
	_, _ = fmt.Fprintln(os.Stderr, "[1] Create Signer")
	signer, err = common.CreateSigner()
	check(err)

	// 2. Prepare TARget (pun intended) and add files and signatures
	_, _ = fmt.Fprintln(os.Stderr, "[2] Bundling Archive")
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
	_, _ = fmt.Fprintln(os.Stderr, "[3] Adding TOC")
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
	_, _ = fmt.Fprintln(os.Stderr, "[4] Encrypting Archive")
	archive, err := arc.Finalize()
	if err != nil {
		return fmt.Errorf("failed encrypting archive: %v", err)
	}

	// 5. Move encrypted file to S3
	_, _ = fmt.Fprintln(os.Stderr, "[5] Save Archive")
	return common.WriteFile(archive)
}

func check(err error, plus ...string) {
	if err != nil {
		log.Fatalln(err, plus)
	}
}
