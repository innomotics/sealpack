package common

import (
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func Test_WriteFile(t *testing.T) {
	// Arrange
	Seal.Output = filepath.Join(TestFilePath, "test.out")
	assert.NoFileExists(t, Seal.Output)
	content := []byte("Hold your breath and count to 10.")

	// Act
	err := WriteFile(content)
	assert.Nil(t, err)

	// Assert
	assert.FileExists(t, Seal.Output)
	defer os.Remove(Seal.Output)
	cnt, err := os.ReadFile(Seal.Output)
	assert.Nil(t, err)
	assert.Equal(t, content, cnt)
}

func Test_WriteFileStdout(t *testing.T) {
	// Arrange
	Seal.Output = "-"
	content := []byte("Hold your breath and count to 10.")
	var err error
	stdout, err = os.CreateTemp("/tmp", "test.tmp")
	defer func() { stdout = os.Stdout }()
	defer os.Remove(stdout.Name())
	assert.Nil(t, err)

	// Act
	err = WriteFile(content)
	assert.Nil(t, err)
	_, err = stdout.Seek(0, 0)
	assert.Nil(t, err)

	// Assert
	cnt, err := io.ReadAll(stdout)
	assert.Nil(t, err)
	assert.Equal(t, content, cnt)
}

func Test_WriteFileS3(t *testing.T) {
	// Arrange
	Seal.Output = "s3://somebucket/someprefix/some.object"
	content := []byte("Hold your breath and count to 10.")
	uploadS3 = func(contents []byte, uri string) error {
		assert.Equal(t, content, contents)
		assert.Equal(t, Seal.Output, uri)
		return nil
	}

	// Act
	err := WriteFile(content)
	assert.Nil(t, err)
}

func Test_WriteFileUnallowed(t *testing.T) {
	// Arrange
	Seal.Output = "/sys/class/some.object"
	content := []byte("Hold your breath and count to 10.")
	// Act
	err := WriteFile(content)
	assert.Error(t, err)
}
