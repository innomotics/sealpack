package aws

import (
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"io/ioutil"
	"strings"
	"time"
)

const (
	PresignValidDuration = 5 * time.Minute
	S3UriPrefix          = "s3://"
)

type S3Uri struct {
	Bucket *string
	Key    *string
}

// s3Session represents the AWS S3 Session.
var s3Session *s3.S3

// verifyS3Session
func verifyS3Session() {
	verifyAwsSession()
	if s3Session == nil {
		s3Session = s3.New(sess)
	}
}

// S3DownloadResource downloads an object by its key and returns the contents as byte slice.
func S3DownloadResource(uri string) ([]byte, error) {
	s3uri, err := parseS3Uri(uri)
	if err != nil {
		return nil, err
	}
	objectOut, err := s3Session.GetObject(&s3.GetObjectInput{
		Bucket: s3uri.Bucket,
		Key:    s3uri.Key,
	})
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(objectOut.Body)
}

// S3CreatePresignedDownload creates a presigned link to an object and returns it as string.
func S3CreatePresignedDownload(uri string) (string, error) {
	s3uri, err := parseS3Uri(uri)
	if err != nil {
		return "", err
	}
	req, _ := s3Session.GetObjectRequest(&s3.GetObjectInput{
		Bucket: s3uri.Bucket,
		Key:    s3uri.Key,
	})
	return req.Presign(PresignValidDuration)
}

// S3UploadArchive uploads the byte slice of the archive to S3.
func S3UploadArchive(contents []byte, uri string) error {
	s3uri, err := parseS3Uri(uri)
	if err != nil {
		return err
	}
	_, err = s3Session.PutObject(&s3.PutObjectInput{
		Bucket: s3uri.Bucket,
		Key:    s3uri.Key,
		Body:   bytes.NewReader(contents),
	})
	if err != nil {
		return err
	}
	return nil
}

// parseS3Uri parses a string-based URI with a s3:// file wrapper to bucket and key
func parseS3Uri(s3uri string) (*S3Uri, error) {
	parts := strings.SplitN(strings.TrimPrefix(s3uri, S3UriPrefix), "/", 1)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid S3 URI")
	}
	return &S3Uri{
		Bucket: aws.String(parts[0]),
		Key:    aws.String(parts[1]),
	}, nil
}
