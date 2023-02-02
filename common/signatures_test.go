package common

import (
	"crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var re = regexp.MustCompile(`[^a-zA-Z0-9]`)

func Test_AvailableHashes(t *testing.T) {
	list := []string{"SHA224", "SHA256", "SHA384", "SHA512"}
	for _, l := range list {
		hsh, ex := availableHashes[l]
		assert.True(t, ex)
		assert.Equal(t, l, re.ReplaceAllString(hsh.String(), ""))
	}
	// Some invalid ones
	list = []string{"MD5", "SHA1", "MD5SHA1", "SHA128", "RIPEMD160"}
	for _, l := range list {
		hsh, ex := availableHashes[l]
		assert.False(t, ex)
		assert.Equal(t, crypto.Hash(0), hsh)
	}
}

func Test_GetHashAlgorithm(t *testing.T) {
	list := []string{"SHA224", "SHA256", "SHA384", "SHA512"}
	for _, l := range list {
		assert.Equal(t, availableHashes[l], GetHashAlgorithm(l))
	}
	// Some invalid ones
	list = []string{"MD5", "SHA1", "MD5SHA1", "SHA128", "RIPEMD160"}
	for _, l := range list {
		assert.Equal(t, crypto.SHA512, GetHashAlgorithm(l))
	}
}

func Test_NewSignatureList(t *testing.T) {
	list := []string{"SHA224", "SHA256", "SHA384", "SHA512"}
	for _, l := range list {
		assert.IsType(t, &FileSignatures{}, NewSignatureList(l))
		assert.Equal(t, availableHashes[l].New(), hashAlgo)
	}
	// Some invalid ones
	list = []string{"MD5", "SHA1", "MD5SHA1", "SHA128", "RIPEMD160"}
	for _, l := range list {
		assert.IsType(t, &FileSignatures{}, NewSignatureList(l))
		assert.Equal(t, crypto.SHA512.New(), hashAlgo)
	}
}

func Test_FileSignatures_AddFileHashSave(t *testing.T) {
	sl := NewSignatureList("SHA256")
	name := "foo/bar/public.pem"
	content, _ := os.ReadFile(filepath.Join(TestFilePath, "public.pem"))
	assert.NoError(t, sl.AddFile(name, content))
	assert.Equal(t, 32, len((*sl)[name]))
	// Test Hash
	assert.Equal(t,
		[]byte(strings.Join([]string{name, (*sl)[name]}, Delimiter)+"\n"),
		sl.Bytes(),
	)
	// Test Save
	tmp, _ := os.CreateTemp("/tmp", "test")
	defer os.Remove(tmp.Name())
	sl.Save(tmp.Name())
	_, _ = tmp.Seek(0, 0)
	of, err := io.ReadAll(tmp)
	assert.NoError(t, err)
	assert.Equal(t, sl.Bytes(), of)
}

func Test_FileSignatures_AddFileNil(t *testing.T) {
	sl := NewSignatureList("SHA256")
	name := "foo/bar/public.pem"
	nilHash := "\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4șo\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U"
	assert.NoError(t, sl.AddFile(name, nil))
	assert.Equal(t, nilHash, (*sl)[name])
}

func Test_FileSignatures_AddFileEmpty(t *testing.T) {
	sl := NewSignatureList("SHA256")
	name := "foo/bar/public.pem"
	nilHash := "\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4șo\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U"
	assert.NoError(t, sl.AddFile(name, []byte{}))
	assert.Equal(t, nilHash, (*sl)[name])
}

func Test_FileSignatures_Equals(t *testing.T) {
	// same content
	slNull := NewSignatureList("SHA256")
	assert.NoError(t, slNull.AddFile("foo", nil))
	slEmpty := NewSignatureList("SHA256")
	assert.NoError(t, slEmpty.AddFile("foo", []byte{}))
	assert.True(t, slNull.Equals(slEmpty))
	// other name
	slOtherName := NewSignatureList("SHA256")
	assert.NoError(t, slOtherName.AddFile("bar", nil))
	assert.False(t, slNull.Equals(slOtherName))
	// other content
	slOtherContent := NewSignatureList("SHA256")
	assert.NoError(t, slOtherContent.AddFile("foo", []byte("bar")))
	assert.False(t, slNull.Equals(slOtherContent))
}
