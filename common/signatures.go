package common

import (
	"crypto"
	"hash"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// A FileSignatures is represented by its path and the hash of the file
type FileSignatures map[string]string

// Delimiter delimits the file name from its hash
const Delimiter = ":"

// availableHashes maps names of available hashes to their crypto.Hash
var availableHashes = map[string]crypto.Hash{
	"SHA224": crypto.SHA224,
	"SHA256": crypto.SHA256,
	"SHA384": crypto.SHA384,
	"SHA512": crypto.SHA512,
	/*
		"MD5SHA1":    crypto.MD5SHA1,
		"RIPEMD160":  crypto.RIPEMD160,
		"SHA3224":    crypto.SHA3_224,
		"SHA3256":    crypto.SHA3_256,
		"SHA3384":    crypto.SHA3_384,
		"SHA3512":    crypto.SHA3_512,
		"SHA512224":  crypto.SHA512_224,
		"SHA512256":  crypto.SHA512_256,
		"BLAKE2s256": crypto.BLAKE2s_256,
		"BLAKE2b256": crypto.BLAKE2b_256,
		"BLAKE2b384": crypto.BLAKE2b_384,
		"BLAKE2b512": crypto.BLAKE2b_512,
	*/
}

var (
	hashAlgo hash.Hash
)

// GetHashAlgorithm retrieves a crypto.Hash for a name.
// if no available name is provided, SHA512 is returned.
func GetHashAlgorithm(algo string) crypto.Hash {
	re := regexp.MustCompilePOSIX(`[^a-zA-Z0-9]`)
	h, ok := availableHashes[re.ReplaceAllString(algo, "")]
	if !ok {
		h = crypto.SHA512
	}
	return h
}

// NewSignatureList creates a new signature list
func NewSignatureList(algo string) *FileSignatures {
	s := &FileSignatures{}
	hashAlgo = GetHashAlgorithm(algo).New()
	return s
}

// AddFile hashes a file and its contents and adds it to the list
func (f *FileSignatures) AddFile(name string, contents []byte) error {
	hashAlgo.Reset()
	if _, err := hashAlgo.Write(contents); err != nil {
		return err
	}
	(*f)[name] = string(hashAlgo.Sum(nil))
	return nil
}

// AddFileFromReader hashes a file and its contents and adds it to the list
func (f *FileSignatures) AddFileFromReader(name string, contents io.Reader) (err error) {
	hashAlgo.Reset()
	if _, err = io.Copy(hashAlgo, contents); err != nil {
		return err
	}
	(*f)[name] = string(hashAlgo.Sum(nil))
	return nil
}

// Bytes gets the list formatted as []byte
func (f *FileSignatures) Bytes() []byte {
	keys := make([]string, 0, len(*f))
	for k := range *f {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sb := strings.Builder{}
	for _, fileName := range keys {
		_, _ = sb.WriteString(fileName + Delimiter + (*f)[fileName] + "\n")
	}
	return []byte(sb.String())
}

// Save the signatures list to a file
func (f *FileSignatures) Save(name string) error {
	return os.WriteFile(name, f.Bytes(), 0777)
}

// Equals compares 2 FileSignatures for equality
func (f *FileSignatures) Equals(other *FileSignatures) bool {
	for k, v := range *f {
		if (*other)[k] != v {
			return false
		}
	}
	return true
}
