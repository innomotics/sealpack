package main

import (
	"bytes"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"io/ioutil"
)

// s3Session represents the AWS S3 Session.
var s3Session *s3.S3

// s3DownloadResource downloads an object by its key and returns the contents as byte slice.
func s3DownloadResource(key string) ([]byte, error) {
	objectOut, err := s3Session.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(objectOut.Body)
}

// s3CreatePresignedDownload creates a presigned link to an object and returns it as string.
func s3CreatePresignedDownload() (string, error) {
	req, _ := s3Session.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(BucketName),
		Key:    aws.String(PrefixOut + "/" + DownloadObjectFilename),
	})
	return req.Presign(PresignValidDuration)
}

// s3UploadArchive uploads the byte slice of the archive to S3.
func s3UploadArchive(archive []byte) error {
	_, err := s3Session.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(BucketName),
		Key:    aws.String(PrefixOut + "/" + DownloadObjectFilename),
		Body:   bytes.NewReader(archive),
	})
	if err != nil {
		return err
	}
	return nil
}
