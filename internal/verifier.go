package internal

import (
	"archive/tar"
	"bytes"
	"fmt"
	"github.com/apex/log"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/sigstore/pkg/signature"
	"io"
	"os"
)

type tagList []*name.Tag

// Verifier contains all data necessary to verify the archive's integrity
type Verifier struct {
	sigVerifier  signature.Verifier
	toc          *bytes.Buffer
	tocSignature *bytes.Buffer
	unsafeTags   tagList
	Signatures   *FileSignatures
}

// NewVerifier Creates a new sealpack integrity verifier structure
func NewVerifier(signingKeyPath, hashingAlgorithm string) (*Verifier, error) {
	var err error
	v := &Verifier{}
	v.sigVerifier, err = CreateVerifier(signingKeyPath)
	if err != nil {
		return nil, err
	}
	v.Signatures = NewSignatureList(hashingAlgorithm)
	return v, nil
}

// AddTocComponent adds a TOC or TOC-Signature from a tar reader
func (v *Verifier) AddTocComponent(h *tar.Header, r io.Reader) (err error) {
	if h.Name == TocFileName {
		v.toc = new(bytes.Buffer)
		if _, err = io.Copy(v.toc, r); err != nil {
			return err
		}
	} else {
		v.tocSignature = new(bytes.Buffer)
		if _, err = io.Copy(v.tocSignature, r); err != nil {
			return err
		}
	}
	return nil
}

// AddUnsafeTag adds an unsafe tag to the list
func (v *Verifier) AddUnsafeTag(t *name.Tag) {
	v.unsafeTags = append(v.unsafeTags, t)
}

// Verify checks the final integrity of the sealed archive.
// Rolls back files or tags if integrity was not verified
func (v *Verifier) Verify(outputPath, namespace, targetRegistry string) (err error) {
	// Test if TOC matches collected signatures TOC amd then verify that the TOC signature matches the binary TOC
	if bytes.Compare(v.toc.Bytes(), v.Signatures.Bytes()) != 0 {
		return fmt.Errorf("tocs not matching")
	}
	if err = v.sigVerifier.VerifySignature(v.tocSignature, v.toc); err != nil {
		// As streaming is done before checking the Signature, rollback all
		// 1) Rollback Files
		if errInner := os.RemoveAll(outputPath); errInner != nil {
			log.Errorf("Could not rollback files: %s\n", err.Error())
		}
		// 2) Rollback Tags
		if errInner := RemoveAll(namespace, targetRegistry, v.unsafeTags); errInner != nil {
			log.Errorf("Could not rollback images: %s\n", err.Error())
		}
		return err
	}
	return
}
