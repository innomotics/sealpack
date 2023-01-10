package common

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"log"
	"os"
	"sealpack/shared"
	"strings"
)

type SealConfig struct {
	PrivKeyPath          string
	RecipientPubKeyPaths []string
	Seal                 bool
	HashingAlgorithm     string
	Files                []string
	ImageNames           []string
	Images               []shared.ContainerImage
	Output               string
}

type UnsealConfig struct {
	PrivkeyPath string
	TargetPath  string
}

const (
	DefaultRegistry = "docker.io"
	DefaultTag      = "latest"
)

var (
	// rootCmd describes the main cobra.Command
	rootCmd = &cobra.Command{
		Use:  "sealpack",
		Long: "A cryptographic sealing packager",
	}
	// sealCmd describes the `trigger` subcommand as cobra.Command
	sealCmd = &cobra.Command{
		Use:   "seal",
		Short: "Create sealed archive",
		Long:  "Create a sealed package",
		PreRun: func(cmd *cobra.Command, args []string) {
			if contents != "" {
				if err := readConfiguration(contents); err != nil {
					log.Fatal("invalid configuration file provided")
				}
			}
			if len(Seal.ImageNames) > 0 {
				parseImages()
			}
		},
	}
	// unsealCmd describes the `unpack` subcommand as cobra.Command
	unsealCmd = &cobra.Command{
		Use:   "unseal [path to sealed file]",
		Short: "Unpacks a sealed archive",
		Long:  "Unpacks a sealed archive if the provided private key is valid",
		Args:  cobra.ExactArgs(1),
	}

	contents string
	Seal     *SealConfig
	Unseal   *UnsealConfig
)

func IsSealCmd() bool {
	return sealCmd.CalledAs() == "seal"
}

func IsUnsealCmd() bool {
	return unsealCmd.CalledAs() == "unseal"
}

// ParseCommands is configuring all cobra commands and execute them
func ParseCommands() error {
	Seal = &SealConfig{}
	Unseal = &UnsealConfig{}

	rootCmd.Commands()

	rootCmd.AddCommand(sealCmd)
	sealCmd.Flags().StringVarP(&Seal.PrivKeyPath, "privkey", "p", "", "Path to the private signing key. AWS KMS keys can be used with awskms:/// prefix")
	sealCmd.Flags().StringSliceVarP(&Seal.RecipientPubKeyPaths, "recipient-pubkey", "r", make([]string, 0), "Paths of recipients' public keys")
	sealCmd.Flags().StringVarP(&Seal.Output, "output", "o", "", "Filename to store the result in")
	_ = sealCmd.MarkFlagRequired("privkey")
	_ = sealCmd.MarkFlagRequired("recipient-pubkey")
	sealCmd.Flags().StringVarP(&contents, "contents", "c", "", "Provide all contents as a central configurations file")
	sealCmd.Flags().BoolVarP(&Seal.Seal, "seal", "s", true, "Whether to seal the archive after packing")
	sealCmd.Flags().StringSliceVarP(&Seal.Files, "file", "f", make([]string, 0), "Path to the files to be added")
	sealCmd.Flags().StringSliceVarP(&Seal.ImageNames, "image", "i", make([]string, 0), "Name of container images to be added")
	sealCmd.Flags().StringVarP(&Seal.HashingAlgorithm, "hashing-algorithm", "a", "SHA3_512", "Name of hashing algorithm to be used")

	rootCmd.AddCommand(unsealCmd)
	unsealCmd.Flags().StringVarP(&Unseal.PrivkeyPath, "pubkey", "p", "", "Path to the private key")
	unsealCmd.Flags().StringVarP(&Unseal.TargetPath, "target", "t", ".", "Target path to unpack the contents to")

	return rootCmd.Execute()
}

// readConfiguration searches for the latest configuration json-file and reads the contents.
// The contents are parsed as a slice of PackageContent.
func readConfiguration(params string) error {
	data, err := os.ReadFile(params)
	if err != nil {
		return err
	}
	var contents shared.ArchiveContents
	err = json.Unmarshal(data, &contents)
	if err != nil {
		return err
	}
	Seal.Files = contents.Files
	Seal.Images = contents.Images
	return nil
}

// parseImages parses container images into ContainerImage format.
func parseImages() {
	for _, img := range Seal.ImageNames {
		image := shared.ContainerImage{}
		reg := strings.SplitN(img, "/", 1)
		if len(reg) < 2 { // No registry provided; assume docker hub
			image.Registry = DefaultRegistry
			reg = append(reg, reg[0])
		} else {
			image.Registry = reg[0]
		}
		tag := strings.Split(reg[1], ":")
		if len(tag) < 2 { // No tag provided; assume latest
			image.Tag = DefaultTag
		} else {
			image.Tag = tag[1]
		}
		image.Name = tag[0]
		Seal.Images = append(Seal.Images, image)
	}
	Seal.ImageNames = nil
}
