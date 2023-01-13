package main

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"log"
	"os"
	"sealpack/common"
	"sealpack/shared"
	"strings"
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
		Run: func(cmd *cobra.Command, args []string) {
			if contents != "" {
				if err := readConfiguration(contents); err != nil {
					log.Fatal("invalid configuration file provided")
				}
			}
			if len(common.Seal.ImageNames) > 0 {
				parseImages()
			}
			check(sealCommand())
		},
	}
	// inspectCmd describes the `inspect` subcommand as cobra.Command
	inspectCmd = &cobra.Command{
		Use:   "inspect",
		Short: "Inspects a sealed archive",
		Long:  "Inspects a sealed archive and allows for identifying any errors",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.SealedFile = args[0]
			check(inspectCommand())
		},
	}
	// unsealCmd describes the `unpack` subcommand as cobra.Command
	unsealCmd = &cobra.Command{
		Use:   "unseal",
		Short: "Unpacks a sealed archive",
		Long:  "Unpacks a sealed archive if the provided private key is valid",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			common.SealedFile = args[0]
			check(unsealCommand())
		},
	}

	contents string
)

func IsSealCmd() bool {
	return sealCmd.CalledAs() == "seal"
}

func IsInspectCommand() bool {
	return inspectCmd.CalledAs() == "inspect"
}

func IsUnsealCmd() bool {
	return unsealCmd.CalledAs() == "unseal"
}

// ParseCommands is configuring all cobra commands and execute them
func ParseCommands() error {
	common.Seal = &common.SealConfig{}
	common.Unseal = &common.UnsealConfig{}

	rootCmd.Commands()

	rootCmd.AddCommand(sealCmd)
	sealCmd.Flags().StringVarP(&common.Seal.PrivKeyPath, "privkey", "p", "", "Path to the private signing key. AWS KMS keys can be used with awskms:/// prefix")
	sealCmd.Flags().StringSliceVarP(&common.Seal.RecipientPubKeyPaths, "recipient-pubkey", "r", make([]string, 0), "Paths of recipients' public keys")
	sealCmd.Flags().StringVarP(&common.Seal.Output, "output", "o", "", "Filename to store the result in")
	_ = sealCmd.MarkFlagRequired("privkey")
	_ = sealCmd.MarkFlagRequired("recipient-pubkey")
	sealCmd.Flags().StringVarP(&contents, "contents", "c", "", "Provide all contents as a central configurations file")
	sealCmd.Flags().BoolVarP(&common.Seal.Seal, "seal", "s", true, "Whether to seal the archive after packing")
	sealCmd.Flags().StringSliceVarP(&common.Seal.Files, "file", "f", make([]string, 0), "Path to the files to be added")
	sealCmd.Flags().StringSliceVarP(&common.Seal.ImageNames, "image", "i", make([]string, 0), "Name of container images to be added")
	sealCmd.Flags().StringVarP(&common.Seal.HashingAlgorithm, "hashing-algorithm", "a", "SHA3_512", "Name of hashing algorithm to be used")

	rootCmd.AddCommand(inspectCmd)

	rootCmd.AddCommand(unsealCmd)
	unsealCmd.Flags().StringVarP(&common.Unseal.PrivKeyPath, "privkey", "p", "", "Private key of the receiver")
	unsealCmd.Flags().StringVarP(&common.Unseal.SigningKeyPath, "signer-key", "s", "", "Public key of the signing entity")
	unsealCmd.Flags().StringVarP(&common.Unseal.OutputPath, "output", "o", "output", "Output path to unpack the contents to")
	_ = sealCmd.MarkFlagRequired("privkey")
	_ = sealCmd.MarkFlagRequired("signer-key")
	unsealCmd.Flags().StringVarP(&common.Unseal.HashingAlgorithm, "hashing-algorithm", "a", "SHA3_512", "Name of hashing algorithm to be used")

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
	common.Seal.Files = contents.Files
	common.Seal.Images = contents.Images
	return nil
}

// parseImages parses container images into ContainerImage format.
func parseImages() {
	for _, img := range common.Seal.ImageNames {
		image := shared.ContainerImage{}
		reg := strings.SplitN(img, "/", 2)
		if len(reg) < 2 { // No registry provided; assume docker hub
			image.Registry = common.DefaultRegistry
			reg = append(reg, reg[0])
		} else {
			image.Registry = reg[0]
		}
		tag := strings.Split(reg[1], ":")
		if len(tag) < 2 { // No tag provided; assume latest
			image.Tag = common.DefaultTag
		} else {
			image.Tag = tag[1]
		}
		image.Name = tag[0]
		common.Seal.Images = append(common.Seal.Images, image)
	}
	common.Seal.ImageNames = nil
}
