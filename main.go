package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	kmssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type PackageContent struct {
	Name    string
	Tag     string
	IsImage bool
}

type LayerConfig struct {
	MediaType string
	Digest    string
	Size      int
}

type Manifest struct {
	SchemaVersion int
	Config        LayerConfig
	Layers        []LayerConfig
	Annotations   map[string]string
}

type OutManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

const (
	SecretName             = "dev/aeskey"
	BucketName             = "ecs-updater"
	KeyArn                 = "arn:aws:kms:eu-central-1:920225275827:key/bd52e3aa-5197-446a-8ee5-e3f2db29ad9b"
	EcrRepository          = "920225275827.dkr.ecr.eu-central-1.amazonaws.com"
	PrefixOut              = "tmp"
	DownloadObjectFilename = "Update.IPC127E.ecs"
)

var (
	s3Session  *s3.S3
	kmsSession *kms.KMS
	ecrSession *ecr.ECR
	smSession  *secretsmanager.SecretsManager

	gzipWriter *gzip.Writer
	tarWriter  *tar.Writer
	tarOut     *bufio.Writer
	buffer     *bytes.Buffer

	contents = []PackageContent{
		{
			Name:    "ipc-demo-frontend",
			Tag:     "v0.2",
			IsImage: true,
		},
		{
			Name:    "ipc-demo-backend",
			Tag:     "v0.3",
			IsImage: true,
		},
		{
			Name:    "ipc-demo-updater",
			Tag:     "v3.0",
			IsImage: true,
		},
		{
			Name: "job.yaml",
		},
	}
)

func HandleRequest(ctx context.Context) (string, error) {
	// 0. Prepare
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-central-1")},
	)
	if err != nil {
		return "1", err
	}
	s3Session = s3.New(sess)
	kmsSession = kms.New(sess)
	ecrSession = ecr.New(sess)
	smSession = secretsmanager.New(sess)
	signer, err := kmssigner.LoadSignerVerifier("awskms:///" + KeyArn)
	if err != nil {
		return "", err
	}

	// 1. Prepare TARget (pun intended) and add files and signatures
	createArchive()
	var body []byte
	var imgName string
	for _, content := range contents {
		imgName = content.Name
		if content.IsImage {
			body, err = downloadEcrImage(&content)
			os.WriteFile("test.tar", body, 0775)
			if err != nil {
				return "Failed receiving image", err
			}
			imgName += ".oci"
		} else {
			body, err = downloadS3Resource(content.Name)
			if err != nil {
				return "Failed downloading", err
			}
		}
		signature, err := signer.SignMessage(bytes.NewReader(body))
		if err != nil {
			return "failed signing", err
		}
		if err = addToArchive(imgName, body, signature); err != nil {
			return "failed taring", nil
		}
	}

	// 2. Encrypt archive
	closeArchive()
	archive, err := encryptArchive(buffer.Bytes())
	if err != nil {
		return "failed encrypting archive", err
	}

	// 3. Move tar file to S3
	poo, err := s3Session.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(BucketName),
		Key:    aws.String(PrefixOut + "/" + DownloadObjectFilename),
		Body:   bytes.NewReader(archive),
	})
	if err != nil {
		return "failed uploading to S3", err
	}
	fmt.Println(poo.String())

	// 4. Create preshared key
	req, _ := s3Session.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(BucketName),
		Key:    aws.String(PrefixOut + "/" + DownloadObjectFilename),
	})
	urlStr, err := req.Presign(5 * time.Minute)

	if err != nil {
		return "failed presigning", err
	}
	return urlStr, nil
}

func downloadEcrImage(content *PackageContent) ([]byte, error) {
	imageDetails, err := ecrSession.BatchGetImage(&ecr.BatchGetImageInput{
		RepositoryName: &content.Name,
		ImageIds: []*ecr.ImageIdentifier{
			{ImageTag: &content.Tag},
		},
	})
	if err != nil {
		return nil, err
	}
	manifest := Manifest{}
	if err = json.Unmarshal([]byte(*imageDetails.Images[0].ImageManifest), &manifest); err != nil {
		return nil, err
	}

	// prepare image tar
	imageTarBuf := new(bytes.Buffer)
	imageTarWriter := tar.NewWriter(imageTarBuf)

	om := make([]OutManifest, 1)
	// 0. Add base tag
	om[0].RepoTags = make([]string, 1)
	om[0].RepoTags[0] = fmt.Sprintf("%s/%s:%s", EcrRepository, content.Name, content.Tag)
	// 1. Download Config
	data, err := downloadLayer(&content.Name, manifest.Config)
	if err != nil {
		return nil, err
	}
	om[0].Config = manifest.Config.Digest[7:] + ".json"
	if err = writeToTar(imageTarWriter, &om[0].Config, data); err != nil {
		return nil, err
	}
	// 2. Add all layers (gzipped on pull, so unzip the downloaded byte stream before adding it)
	om[0].Layers = make([]string, 0, len(manifest.Layers))
	var dataBuf bytes.Buffer
	for _, layer := range manifest.Layers {
		data, err = downloadLayer(&content.Name, layer)
		if err != nil {
			return nil, err
		}
		om[0].Layers = append(om[0].Layers, layer.Digest[7:]+".tar")
		gunzip, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		if _, err = dataBuf.ReadFrom(gunzip); err != nil {
			return nil, err
		}
		if err = writeToTar(imageTarWriter, &om[0].Layers[len(om[0].Layers)-1], dataBuf.Bytes()); err != nil {
			return nil, err
		}
	}
	// 3. Add the manifest
	outManifestBytes, err := json.Marshal(om)
	if err != nil {
		return nil, err
	}
	if err = writeToTar(imageTarWriter, aws.String("manifest.json"), outManifestBytes); err != nil {
		return nil, err
	}
	if err = imageTarWriter.Close(); err != nil {
		return nil, err
	}
	return imageTarBuf.Bytes(), nil
}

func downloadLayer(image *string, config LayerConfig) ([]byte, error) {
	download, err := ecrSession.GetDownloadUrlForLayer(&ecr.GetDownloadUrlForLayerInput{
		RepositoryName: image,
		LayerDigest:    aws.String(config.Digest),
	})
	if err != nil {
		return nil, err
	}
	cli := http.Client{}
	resp, err := cli.Get(*download.DownloadUrl)
	if err != nil {
		return nil, err
	}
	buf := bytes.Buffer{}
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

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

func getEncryptionKey() ([]byte, error) {
	result, err := smSession.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(SecretName),
	})
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 32)
	base64.StdEncoding.Decode(buffer, []byte(*result.SecretString))
	return buffer, err
}

func downloadS3Resource(key string) ([]byte, error) {
	objectOut, err := s3Session.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(objectOut.Body)
}

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

func createArchive() {
	buffer = new(bytes.Buffer)
	gzipWriter = gzip.NewWriter(buffer)
	tarWriter = tar.NewWriter(gzipWriter)
}

func closeArchive() {
	gzipWriter.Close()
	tarWriter.Close()
}

func main() {
	//////// LAMBDA USAGE //////
	lambda.Start(HandleRequest)
	//////// OFFLINE USAGE /////
	//result, err := HandleRequest(context.TODO())
	//fmt.Printf("Result: %v\nError: %v\n\n", result, err)
}
