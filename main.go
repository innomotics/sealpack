package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"log"
	"os"
	"sealpack/common"
	"sealpack/shared"
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
	arc := shared.CreateArchive()
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
	reader := bytes.NewReader(signatures.Bytes())
	tocSignature, err := signer.SignMessage(reader, options.NoOpOptionImpl{})
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
	// Now create encryption key and seal them for all recipients
	envelope := shared.Envelope{
		HashAlgorithm: common.GetConfiguredHashAlgorithm(),
	}
	var symKey []byte
	if envelope.PayloadEncrypted, symKey, err = common.Encrypt(archive); err != nil {
		return err
	}
	envelope.NumReceivers = uint16(len(common.Seal.RecipientPubKeyPaths))
	envelope.ReceiverKeys = make([][]byte, envelope.NumReceivers)
	for iKey, recipientPubKeyPath := range common.Seal.RecipientPubKeyPaths {
		var recPubKey *rsa.PublicKey
		if recPubKey, err = common.LoadPublicKey(recipientPubKeyPath); err != nil {
			return err
		}
		if envelope.ReceiverKeys[iKey], err = rsa.EncryptPKCS1v15(rand.Reader, recPubKey, symKey); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stderr, "keys: %v %v\n", len(envelope.ReceiverKeys[iKey]), recPubKey.Size())
		if len(envelope.ReceiverKeys[iKey]) != recPubKey.Size() {
			return fmt.Errorf("key size must be %d bits", common.KeySizeBit)
		}
	}

	// 5. Move encrypted file to S3
	_, _ = fmt.Fprintln(os.Stderr, "[5] Save Archive")
	return common.WriteFile(envelope.ToBytes())
}

func check(err error, plus ...string) {
	if err != nil {
		log.Fatalln(err, plus)
	}
}
