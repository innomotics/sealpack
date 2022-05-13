package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	kmssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	"io/ioutil"
	"time"
)

const (
	BucketName             = "ecs-updater"
	KeyArn                 = "arn:aws:kms:eu-central-1:920225275827:key/31497c03-b05a-4667-9690-c33decc7bbea"
	PrefixImages           = "images"
	PrefixOut              = "tmp"
	DownloadObjectFilename = "Update.IPC127E.ecs"
)

var (
	s3Session  *s3.S3
	kmsSession *kms.KMS

	gzipWriter *gzip.Writer
	tarWriter  *tar.Writer
	tarOut     *bufio.Writer
	buffer     *bytes.Buffer

	images = map[string]string{
		"ipc-demo-frontend.oci": PrefixImages + "/ipc-demo-frontend/v0.2.oci",
		"ipc-demo-backend.oci":  PrefixImages + "/ipc-demo-backend/v0.3.oci",
		"ipc-demo-updater.oci":  PrefixImages + "/ipc-demo-updater/v3.0.oci",
		"job.yaml":              "job.yaml",
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
	signer, err := kmssigner.LoadSignerVerifier("awskms:///" + KeyArn)
	if err != nil {
		return "", err
	}

	// 1. Prepare TARget (pun intended) and add files and signatures
	createArchive()
	for imgName, imgTag := range images {
		var body []byte
		body, err = downloadS3Resource(imgTag)
		if err != nil {
			return "Failed downloading", err
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

func encryptArchive(body []byte) ([]byte, error) {
	aesKey, err := downloadS3Resource("aeskey.bin")
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
	if err := tarWriter.WriteHeader(&tar.Header{
		Name:    imgName,
		Size:    int64(len(contents)),
		Mode:    0755,
		ModTime: time.Now(),
	}); err != nil {
		return err
	}
	if _, err := tarWriter.Write(contents); err != nil {
		return err
	}
	fmt.Println("Added " + imgName)
	// 2. Add signature
	if err := tarWriter.WriteHeader(&tar.Header{
		Name:    imgName + ".sig",
		Size:    int64(len(signature)),
		Mode:    0755,
		ModTime: time.Now(),
	}); err != nil {
		return err
	}
	if _, err := tarWriter.Write(signature); err != nil {
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
	lambda.Start(HandleRequest)
}
