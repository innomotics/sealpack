package common

import (
	"archive/tar"
	"bytes"
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name             string
		SigningKeyPath   string
		HashingAlgorithm string
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			name:             "Standard configuration",
			SigningKeyPath:   "../test/public.pem",
			HashingAlgorithm: "SHA512",
			wantErr:          assert.NoError,
		},
		{
			name:             "Try to load private key",
			SigningKeyPath:   "../test/private.pem",
			HashingAlgorithm: "SHA512",
			wantErr:          assert.Error,
		},
		{
			name:             "Try to load invalid file",
			SigningKeyPath:   "../test/tmp.bin",
			HashingAlgorithm: "SHA512",
			wantErr:          assert.Error,
		},
		{
			name:             "Try to load nonexistent file",
			SigningKeyPath:   "../fnord/foo.bar",
			HashingAlgorithm: "SHA512",
			wantErr:          assert.Error,
		},
		{
			name:             "Try to load unallowed HashingAlgorithm",
			SigningKeyPath:   "../test/private.pem",
			HashingAlgorithm: "SHA3512",
			wantErr:          assert.Error,
		},
		{
			name:             "Try to load invalid HashingAlgorithm",
			SigningKeyPath:   "../test/private.pem",
			HashingAlgorithm: "HAIMIS384",
			wantErr:          assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &UnsealConfig{}
			fmt.Println(tt.SigningKeyPath)
			config.SigningKeyPath = tt.SigningKeyPath
			config.HashingAlgorithm = tt.HashingAlgorithm
			_, err := NewVerifier(config)
			tt.wantErr(t, err, fmt.Sprintf("NewVerifier()"))
		})
	}
}

func TestVerifier_AddTocComponent(t *testing.T) {
	type args struct {
		h *tar.Header
		r []byte
	}
	bts := []byte("My foo is my bar!")
	tests := []struct {
		name         string
		args         args
		toc          []byte
		tocSignature []byte
		wantErr      assert.ErrorAssertionFunc
	}{
		{
			name: "Standard TOC",
			args: args{
				h: &tar.Header{Name: ".sealpack.toc"},
				r: bts,
			},
			toc:          bts,
			tocSignature: nil,
			wantErr:      assert.NoError,
		},
		{
			name: "Standard TOC Signature",
			args: args{
				h: &tar.Header{Name: ".sealpack.toc.sig"},
				r: bts,
			},
			toc:          nil,
			tocSignature: bts,
			wantErr:      assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.args.r)
			v := &Verifier{}
			tt.wantErr(t, v.AddTocComponent(tt.args.h, r), fmt.Sprintf("AddTocComponent(%v, %v)", tt.args.h, tt.args.r))
			fmt.Println(string(tt.args.r))
			if tt.toc == nil {
				assert.Nil(t, v.toc)
			} else {
				assert.Equal(t, tt.toc, v.toc.Bytes())
			}
			if tt.tocSignature == nil {
				assert.Nil(t, v.tocSignature)
			} else {
				assert.Equal(t, tt.tocSignature, v.tocSignature.Bytes())
			}

		})
	}
}

func TestVerifier_AddUnsafeTag(t *testing.T) {
	exTag, _ := name.NewTag("foo.bar/repos/tags:v1.23.4-beta2")
	tests := []struct {
		name string
		args *name.Tag
	}{
		{"Add tag", &exTag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				unsafeTags: tagList{},
			}
			assert.Equal(t, 0, len(v.unsafeTags))
			v.AddUnsafeTag(tt.args)
			assert.Equal(t, 1, len(v.unsafeTags))
			assert.Equal(t, "foo.bar/repos/tags:v1.23.4-beta2", v.unsafeTags[0].String())
		})
	}
}

type verifierFields struct {
	sigVerifier  signature.Verifier
	toc          *bytes.Buffer
	tocSignature *bytes.Buffer
	unsafeTags   tagList
	Signatures   *FileSignatures
}

func createValidVerifierFields() verifierFields {
	sigList := NewSignatureList("SHA512")
	_ = sigList.AddFile("Foo", []byte("Bar-Rick-Ade"))
	signer, _ := CreatePKISigner("../test/private.pem")
	signat, _ := signer.SignMessage(bytes.NewReader(sigList.Bytes()))
	verifier, _ := CreatePKIVerifier("../test/public.pem")
	return verifierFields{
		sigVerifier:  verifier,
		toc:          bytes.NewBuffer(sigList.Bytes()),
		tocSignature: bytes.NewBuffer(signat),
		unsafeTags:   tagList{},
		Signatures:   sigList,
	}
}
func TestVerifier_Verify(t *testing.T) {
	manipulatedVerifier := createValidVerifierFields()
	manipulatedVerifier.tocSignature = bytes.NewBuffer([]byte("Fnord"))
	tests := []struct {
		name        string
		fields      verifierFields
		errContains string
	}{
		{
			name: "TOC and signatures not matching",
			fields: verifierFields{
				toc:        bytes.NewBuffer([]byte("Foo")),
				unsafeTags: tagList{},
				Signatures: NewSignatureList("SHA512"),
			},
			errContains: "tocs not matching",
		},
		{
			name:        "Signature wrong",
			fields:      manipulatedVerifier,
			errContains: "crypto/rsa: verification error",
		},
		{
			name:        "All is fine",
			fields:      createValidVerifierFields(),
			errContains: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				sigVerifier:  tt.fields.sigVerifier,
				toc:          tt.fields.toc,
				tocSignature: tt.fields.tocSignature,
				unsafeTags:   tt.fields.unsafeTags,
				Signatures:   tt.fields.Signatures,
			}
			config := &UnsealConfig{
				OutputPath: "../demo",
			}
			if tt.errContains == "" {
				assert.NoError(t, v.Verify(config), fmt.Sprintf("Verify()"))
			} else {
				assert.ErrorContains(t, v.Verify(config), tt.errContains, fmt.Sprintf("Verify()"))
			}
		})
	}
}
