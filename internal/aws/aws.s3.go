package aws

/*
 * Sealpack
 *
 * Copyright (c) Innomotics GmbH, 2023
 *
 * Authors:
 *  Mathias Haimerl <mathias.haimerl@siemens.com>
 *
 * This work is licensed under the terms of the Apache 2.0 license.
 * See the LICENSE.txt file in the top-level directory.
 *
 * SPDX-License-Identifier:	Apache-2.0
 */

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
var (
	s3Session *s3.Client
	s3pc      *s3.PresignClient
)

// verifyS3Session
func verifyS3Session() {
	if s3Session == nil {
		s3Session = s3.New(s3.Options{})
		s3pc = s3.NewPresignClient(s3Session)
	}
}

// S3DownloadResource downloads an object by its key and returns the contents as byte slice.
func S3DownloadResource(uri string) ([]byte, error) {
	s3uri, err := parseS3Uri(uri)
	if err != nil {
		return nil, err
	}
	objectOut, err := s3Session.GetObject(awsCtx, &s3.GetObjectInput{
		Bucket: s3uri.Bucket,
		Key:    s3uri.Key,
	})
	if err != nil {
		return nil, err
	}
	return io.ReadAll(objectOut.Body)
}

// S3CreatePresignedDownload creates a presigned link to an object and returns it as string.
func S3CreatePresignedDownload(uri string) (string, error) {
	s3uri, err := parseS3Uri(uri)
	if err != nil {
		return "", err
	}
	req, err := s3pc.PresignGetObject(awsCtx, &s3.GetObjectInput{
		Bucket: s3uri.Bucket,
		Key:    s3uri.Key,
	}, func(opts *s3.PresignOptions) {
		opts.Expires = PresignValidDuration
	})
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// S3UploadArchive uploads the byte slice of the archive to S3.
func S3UploadArchive(reader io.ReadSeeker, uri string) error {
	verifyS3Session()
	s3uri, err := parseS3Uri(uri)
	if err != nil {
		return err
	}
	_, err = s3Session.PutObject(awsCtx, &s3.PutObjectInput{
		Bucket: s3uri.Bucket,
		Key:    s3uri.Key,
		Body:   reader,
	})
	if err != nil {
		return err
	}
	return nil
}

// parseS3Uri parses a string-based URI with a s3:// file wrapper to bucket and key
func parseS3Uri(s3uri string) (*S3Uri, error) {
	parts := strings.SplitN(strings.TrimPrefix(s3uri, S3UriPrefix), "/", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid S3 URI")
	}
	return &S3Uri{
		Bucket: aws.String(parts[0]),
		Key:    aws.String(parts[1]),
	}, nil
}
