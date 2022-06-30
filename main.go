package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	kmssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ApiParams struct {
	Application string `json:"application"`
	Version     string `json:"version"`
}

func (p ApiParams) GetPackageName(suffix string) string {
	return fmt.Sprintf("%s-%s.%s", p.Application, p.Version, suffix)
}

// PackageContent represents one component to be included in the upgrade package.
// If IsImage is set true, the component will be pulled by Name and Tag from the ECR registry.
// If only name is provided, a static file is expected.
type PackageContent struct {
	Name    string `json:"name"`
	Tag     string `json:"tag"`
	IsImage bool   `json:"is_image"`
}

// Manifest represents an OCI image manifest, typically provided as json.
// For easier handling, this implementation only contains the necessary properties.
// @url https://github.com/opencontainers/image-spec/blob/main/manifest.md
type Manifest struct {
	SchemaVersion int
	Config        Descriptor
	Layers        []Descriptor
	Annotations   map[string]string
}

// Descriptor is a standard OCI descriptor.
// For easier handling, this implementation only contains the necessary properties.
// @url https://github.com/opencontainers/image-spec/blob/main/descriptor.md
type Descriptor struct {
	MediaType string
	Digest    string
	Size      int
}

// OutManifest is the manifest in docker (moby) image format.
// For easier handling, this implementation only contains the necessary properties.
// @url https://github.com/moby/moby/blob/master/image/tarexport/tarexport.go#L18-L24
type OutManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

const (
	SecretName               = "dev/aeskey"
	BucketName               = "ecs-updater"
	KeyArn                   = "arn:aws:kms:eu-central-1:920225275827:key/b07ed28b-e303-4360-9972-6e650aeb3711"
	EcrRepository            = "920225275827.dkr.ecr.eu-central-1.amazonaws.com"
	PrefixOut                = "tmp"
	UpgradeFilenameSuffix    = "ipc"
	PresignValidDuration     = 5 * time.Minute
	ApplicationConfigPattern = "application.v*.json"
	ApplicationConfigDefault = "application.v3.json"
)

var (
	gzipWriter *gzip.Writer
	tarWriter  *tar.Writer
	tarOut     *bufio.Writer
	buffer     *bytes.Buffer

	appConfig []PackageContent
)

// HandleRequest is the central handler for the downloader.
// The 6 steps are described in the function in detail.
func HandleRequest(ctx context.Context, params ApiParams) (string, error) {
	// 1. Prepare AWS services
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-central-1")},
	)
	if err != nil {
		return "unable to create AWS session", err
	}
	s3Session = s3.New(sess)
	ecrSession = ecr.New(sess)
	smSession = secretsmanager.New(sess)
	ecrSession = ecr.New(sess)
	smSession = secretsmanager.New(sess)
	signer, err := kmssigner.LoadSignerVerifier("awskms:///" + KeyArn)
	if err != nil {
		return "", err
	}

	// 2. Load latest application configuration
	fmt.Println("[1] Loading application configuration")
	err = readConfiguration(&params)
	if err != nil {
		return "unable to read application configuration", err
	}

	// 3. Prepare TARget (pun intended) and add files and signatures
	fmt.Println("[2] Preparing Archive")
	createArchive()
	var body []byte
	var imgName string
	for _, content := range appConfig {
		imgName = content.Name
		if content.IsImage {
			body, err = downloadEcrImage(&content)
			os.WriteFile("test.tar", body, 0775)
			if err != nil {
				return "Failed receiving image", err
			}
			imgName += ".oci"
		} else {
			body, err = s3DownloadResource(content.Name)
			if err != nil {
				return "Failed downloading", err
			}
		}
		fmt.Println("[3] Signing " + content.Name)
		signature, err := signer.SignMessage(bytes.NewReader(body))
		if err != nil {
			return "failed signing", err
		}
		if err = addToArchive(imgName, body, signature); err != nil {
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
	if err = addToArchive("app.cfg", []byte(content), signature); err != nil {
		return "failed taring", nil
	}

	// 4. Encrypt archive
	fmt.Println("[4] Encrypting Archive")
	closeArchive()
	archive, err := encryptArchive(buffer.Bytes())
	if err != nil {
		return "failed encrypting archive", err
	}

	// 5. Move encrypted file to S3
	fmt.Println("[5] Uploading Archive")
	ipcFileName := params.GetPackageName(UpgradeFilenameSuffix)
	err = s3UploadArchive(archive, ipcFileName)
	if err != nil {
		return "failed uploading to S3", err
	}

	// 6. Create preshared key and return its url
	fmt.Println("[6] Create Presigned Link")
	urlStr, err := s3CreatePresignedDownload(ipcFileName)
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
		data, err = s3DownloadResource(cfg.GetPackageName("json"))
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

// writeToTar adds a file to a writer using a filename and a byte slice with contents to be written.
func writeToTar(w *tar.Writer, filename *string, contents []byte) error {
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

// encryptArchive applies an AES GCM encryption on a file represented as a byte slice.
// The result is an encrypted file, represented again as a byte slice.
func encryptArchive(body []byte) ([]byte, error) {
	aesKey, err := getEncryptionKey()
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

// addToArchive adds a new file identified by its name to the tar.gz archive.
// The contents and the accompanying signature are added as byte slices.
// The signature's filename is the filename with .sig suffix.
func addToArchive(imgName string, contents []byte, signature []byte) error {
	// 1. Add the OCI image
	if err := writeToTar(tarWriter, &imgName, contents); err != nil {
		return err
	}
	fmt.Println("Added " + imgName)
	// 2. Add signature
	sigName := imgName + ".sig"
	if err := writeToTar(tarWriter, &sigName, signature); err != nil {
		return err
	}
	fmt.Println("Added signature for " + imgName)
	return nil
}

// createArchive opens a stream of writers (tar to gzip to buffer).
// Bytes added to the stream will be added to the tar.gz archive.
// It can be retrieved through the buffer as byte slice.
func createArchive() {
	buffer = new(bytes.Buffer)
	gzipWriter = gzip.NewWriter(buffer)
	tarWriter = tar.NewWriter(gzipWriter)
}

// closeArchive closes the tar and gzip writers.
func closeArchive() {
	gzipWriter.Close()
	tarWriter.Close()
}

// main entrypoint for the downloader application.
// Both the handler for usage with AW Lambda and a standalone executable are provided.
func main() {
	//////// LAMBDA USAGE //////
	lambda.Start(HandleRequest)
	//////// OFFLINE USAGE /////
	//result, err := HandleRequest(context.TODO())
	//fmt.Printf("Result: %v\nError: %v\n\n", result, err)
}
