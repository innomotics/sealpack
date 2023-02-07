package shared

import (
	"path/filepath"
	"strings"
)

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

// ArchiveContents describes all contents for an archive to provide them as a single file.
type ArchiveContents struct {
	Files  []string         `json:"files"`
	Images []ContainerImage `json:"images"`
}

// ContainerImage describes a container image uniquely
type ContainerImage struct {
	Registry string `json:"registry"`
	Name     string `json:"name"`
	Tag      string `json:"tag"`
}

// String creates the image URI form the parts.
func (i *ContainerImage) String() string {
	return i.Registry + "/" + i.Name + ":" + i.Tag
}

const (
	ContainerImagePrefix = ".images"
	OCISuffix            = ".oci"
)

// ToFileName creates a file name to store the image archive in.
func (i *ContainerImage) ToFileName() string {
	return filepath.Join(ContainerImagePrefix, i.Registry, i.Name+":"+i.Tag+OCISuffix)
}

func ParseContainerImage(registry string, name string) *ContainerImage {
	imgParts := strings.Split(strings.TrimSuffix(name, OCISuffix), ":")
	if len(imgParts) < 2 {
		imgParts = append(imgParts, "latest")
	}
	return &ContainerImage{
		Registry: registry,
		Name:     imgParts[0],
		Tag:      imgParts[1],
	}
}
