package common

import (
	"os"
	"sealpack/aws"
	"strings"
)

// WriteFile allows for writing a byte slice to a regular file, S3 bucket or stdout
func WriteFile(contents []byte) error {
	if strings.HasPrefix(Seal.Output, aws.S3UriPrefix) {
		return aws.S3UploadArchive(contents, Seal.Output)
	} else {
		var of *os.File
		var err error
		if Seal.Output == "-" {
			of = os.Stdout
		} else {
			of, err = os.Create(Seal.Output)
			if err != nil {
				return err
			}
			defer of.Close()
		}
		_, err = of.Write(contents)
		return err
	}
}
