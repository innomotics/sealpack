package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"github.com/sigstore/sigstore/pkg/signature"
	"log"
	"os"
	"path/filepath"
	"sealpack/common"
	"strings"
)

const (
	UpgradeFilenameSuffix    = "ipc"
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

	var err error
	signer, err = common.CreateSigner()
	check(err)

	// 2. Load latest application configuration
	fmt.Println("[1] Loading application configuration")
	err = readConfiguration(&params)
	if err != nil {
		return "unable to read application configuration", err
	}

	// 3. Prepare TARget (pun intended) and add files and signatures
	fmt.Println("[2] Preparing Archive")
	common.CreateArchive()
	var body []byte
	var imgName string
	for _, content := range appConfig {
		imgName = content.Name
		if content.IsImage {
			body, err = aws2.downloadEcrImage(&content)
			os.WriteFile("test.tar", body, 0775)
			if err != nil {
				return "Failed receiving image", err
			}
			imgName += ".oci"
		} else {
			body, err = aws2.s3DownloadResource(content.Name)
			if err != nil {
				return "Failed downloading", err
			}
		}
		fmt.Println("[3] Signing " + content.Name)
		signature, err := signer.SignMessage(bytes.NewReader(body))
		if err != nil {
			return "failed signing", err
		}
		if err = common.addToArchive(imgName, body, signature); err != nil {
			return "failed taring", nil
		}
	}
	// 3.1 Add application configuration
	content := fmt.Sprintf("export APP=%s\nexport VERSION=%s", params.Application, params.Version)
	fmt.Println("[3.1] Adding app.cfg")
	signature, err := signer.SignMessage(strings.NewReader(content))
	if err != nil {
		return "failed signing", err
	}
	if err = common.addToArchive("app.cfg", []byte(content), signature); err != nil {
		return "failed taring", nil
	}

	// 4. Encrypt archive
	fmt.Println("[4] Encrypting Archive")

	archive, err := encryptArchive(common.closeArchive())
	if err != nil {
		return "failed encrypting archive", err
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

// readConfiguration searches for the latest configuration json-file and reads the contents.
// The contents are parsed as a slice of PackageContent.
func readConfiguration(cfg *ApiParams) error {
	files, err := filepath.Glob(ApplicationConfigPattern)
	if err != nil {
		return err
	}
	var data []byte
	if len(files) < 1 {
		// read from S3
		data, err = aws2.s3DownloadResource(cfg.GetPackageName("json"))
		if err != nil {
			return err
		}
	} else {
		// Currently, we use only the latest version
		data, err = os.ReadFile(files[len(files)-1])
		if err != nil {
			return err
		}
	}
	err = json.Unmarshal(data, &appConfig)
	return err
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
