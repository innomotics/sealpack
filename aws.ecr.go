package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecr"
	"net/http"
)

// ecrSession represents the AWS ECR Session.
var ecrSession *ecr.ECR

// downloadEcrImage downloads a container image as tar file.
// First, the OCI manifest and subsequently the config json must be obtained from ECS.
// Then the download URLs for all layers must be individually obtained and the layers must be downloaded.
// The layers and the config are added to the tar file; a docker manifest is created and also added.
func downloadEcrImage(content *PackageContent) ([]byte, error) {
	// Download image details, which contains the manifest.
	imageDetails, err := ecrSession.BatchGetImage(&ecr.BatchGetImageInput{
		RepositoryName: &content.Name,
		ImageIds: []*ecr.ImageIdentifier{
			{ImageTag: &content.Tag},
		},
	})
	if err != nil {
		return nil, err
	}
	// Extract the manifest from the image details.
	manifest := Manifest{}
	if err = json.Unmarshal([]byte(*imageDetails.Images[0].ImageManifest), &manifest); err != nil {
		return nil, err
	}
	// Prepare output image tar as bytes buffer
	imageTarBuf := new(bytes.Buffer)
	imageTarWriter := tar.NewWriter(imageTarBuf)
	// Add base tag
	om := make([]OutManifest, 1)
	om[0].RepoTags = make([]string, 1)
	om[0].RepoTags[0] = fmt.Sprintf("%s/%s:%s", EcrRepository, content.Name, content.Tag)
	// Download Config
	data, err := downloadLayer(&content.Name, manifest.Config)
	if err != nil {
		return nil, err
	}
	om[0].Config = manifest.Config.Digest[7:] + ".json"
	if err = writeToTar(imageTarWriter, &om[0].Config, data); err != nil {
		return nil, err
	}
	// Download and add all layers.
	// They are gzipped on pull, so unzip the downloaded byte stream before adding it.
	om[0].Layers = make([]string, 0, len(manifest.Layers))
	var dataBuf bytes.Buffer
	for _, layer := range manifest.Layers {
		data, err = downloadLayer(&content.Name, layer)
		if err != nil {
			return nil, err
		}
		om[0].Layers = append(om[0].Layers, layer.Digest[7:]+".tar")
		gunzip, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		if _, err = dataBuf.ReadFrom(gunzip); err != nil {
			return nil, err
		}
		if err = writeToTar(imageTarWriter, &om[0].Layers[len(om[0].Layers)-1], dataBuf.Bytes()); err != nil {
			return nil, err
		}
	}
	// Add the docker manifest to the tar
	outManifestBytes, err := json.Marshal(om)
	if err != nil {
		return nil, err
	}
	if err = writeToTar(imageTarWriter, aws.String("manifest.json"), outManifestBytes); err != nil {
		return nil, err
	}
	if err = imageTarWriter.Close(); err != nil {
		return nil, err
	}
	return imageTarBuf.Bytes(), nil
}

// downloadLayer requests a download url for a layer, downloads the image and returns it as byte
func downloadLayer(image *string, config Descriptor) ([]byte, error) {
	download, err := ecrSession.GetDownloadUrlForLayer(&ecr.GetDownloadUrlForLayerInput{
		RepositoryName: image,
		LayerDigest:    aws.String(config.Digest),
	})
	if err != nil {
		return nil, err
	}
	cli := http.Client{}
	resp, err := cli.Get(*download.DownloadUrl)
	if err != nil {
		return nil, err
	}
	buf := bytes.Buffer{}
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
