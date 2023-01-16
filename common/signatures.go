package common

import (
	"crypto"
	"hash"
	"os"
	"sort"
	"strings"
)

// A FileSignatures is represented by its path and the hash of the file
type FileSignatures map[string]string

const Delimiter = ":"

var availableHashes = map[string]crypto.Hash{
	"SHA224":      crypto.SHA224,
	"SHA256":      crypto.SHA256,
	"SHA384":      crypto.SHA384,
	"SHA512":      crypto.SHA512,
	"MD5SHA1":     crypto.MD5SHA1,
	"RIPEMD160":   crypto.RIPEMD160,
	"SHA3_224":    crypto.SHA3_224,
	"SHA3_256":    crypto.SHA3_256,
	"SHA3_384":    crypto.SHA3_384,
	"SHA3_512":    crypto.SHA3_512,
	"SHA512_224":  crypto.SHA512_224,
	"SHA512_256":  crypto.SHA512_256,
	"BLAKE2s_256": crypto.BLAKE2s_256,
	"BLAKE2b_256": crypto.BLAKE2b_256,
	"BLAKE2b_384": crypto.BLAKE2b_384,
	"BLAKE2b_512": crypto.BLAKE2b_512,
}

var (
	hashAlgo hash.Hash
)

func GetConfiguredHashAlgorithm(algo string) crypto.Hash {
	h, ok := availableHashes[algo]
	if !ok {
		h = crypto.SHA3_512
	}
	return h
}

func NewSignatureList(algo string) *FileSignatures {
	s := &FileSignatures{}
	hashAlgo = GetConfiguredHashAlgorithm(algo).New()
	return s
}

func (f *FileSignatures) AddFile(name string, contents []byte) error {
	hashAlgo.Reset()
	if _, err := hashAlgo.Write(contents); err != nil {
		return err
	}
	(*f)[name] = string(hashAlgo.Sum(nil))
	return nil
}

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

func (f *FileSignatures) Save(name string) error {
	return os.WriteFile(name, f.Bytes(), 0777)
}

func (f *FileSignatures) Equals(other *FileSignatures) bool {
	for k, v := range *f {
		if (*other)[k] != v {
			return false
		}
	}
	return true
}
