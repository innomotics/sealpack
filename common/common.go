package common

import (
	"github.com/sigstore/sigstore/pkg/signature"
	"sealpack/aws"
	"strings"
)

type PackageContent interface {
	PackagePath() string
}

// ImageContent represents one component to be included in the upgrade package.
// If IsImage is set true, the component will be pulled by Name and Tag from the ECR registry.
// If only name is provided, a static file is expected.
type ImageContent struct {
	Name     string `json:"name"`
	Tag      string `json:"tag"`
	Registry string `json:"registry"`
	IsImage  bool   `json:"is_image"`
}

// Manifest represents an OCI image manifest, typically provided as json.
// For easier handling, this implementation only contains the necessary properties.
// @url https://github.com/opencontainers/image-spec/blob/main/manifest.md
type Manifest struct {
	SchemaVersion int
	Config        Descriptor
	Layers        []Descriptor
	Annotations   map[string]string
}

// Descriptor is a standard OCI descriptor.
// For easier handling, this implementation only contains the necessary properties.
// @url https://github.com/opencontainers/image-spec/blob/main/descriptor.md
type Descriptor struct {
	MediaType string
	Digest    string
	Size      int
}

// OutManifest is the manifest in docker (moby) image format.
// For easier handling, this implementation only contains the necessary properties.
// @url https://github.com/moby/moby/blob/master/image/tarexport/tarexport.go#L18-L24
type OutManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type Signer struct {
	Signer *signature.SignerVerifier
}

func CreateSigner() (signature.Signer, error) {
	if strings.HasPrefix(Seal.PrivKeyPath, "awskms:///") {
		return aws.CreateKmsSigner(Seal.PrivKeyPath)
	}
	// TODO: other potential signing modules
	return CreatePKISigner()
}
