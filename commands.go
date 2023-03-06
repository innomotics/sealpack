package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"path/filepath"
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
				for _, img := range common.Seal.ImageNames {
					common.Seal.Images = append(common.Seal.Images, common.ParseContainerImage(img))
				}
			}
			// public option cannot be used with receiver keys
			if common.Seal.Public && len(common.Seal.RecipientPubKeyPaths) > 0 {
				log.Fatal("Cannot use -public with -recipient-pubkey (illogical error)")
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
	_ = sealCmd.MarkFlagRequired("output")
	sealCmd.Flags().BoolVar(&common.Seal.Public, "public", false, "Don't encrypt, contents are signed only and can be retrieved from any receiver")
	sealCmd.Flags().StringVarP(&contents, "contents", "c", "", "Provide all contents as a central configurations file (supports JSON, YAML)")
	sealCmd.Flags().StringSliceVarP(&common.Seal.Files, "file", "f", make([]string, 0), "Path to the files to be added")
	sealCmd.Flags().StringSliceVarP(&common.Seal.ImageNames, "image", "i", make([]string, 0), "Name of container images to be added")
	sealCmd.Flags().StringVarP(&common.Seal.HashingAlgorithm, "hashing-algorithm", "a", "SHA512", "Name of hashing algorithm to be used")

	rootCmd.AddCommand(inspectCmd)

	rootCmd.AddCommand(unsealCmd)
	unsealCmd.Flags().StringVarP(&common.Unseal.PrivKeyPath, "privkey", "p", "", "Private key of the receiver")
	unsealCmd.Flags().StringVarP(&common.Unseal.SigningKeyPath, "signer-key", "s", "", "Public key of the signing entity")
	unsealCmd.Flags().StringVarP(&common.Unseal.OutputPath, "output", "o", ".", "Output path to unpack the contents to")
	_ = sealCmd.MarkFlagRequired("signer-key")
	unsealCmd.Flags().StringVarP(&common.Unseal.HashingAlgorithm, "hashing-algorithm", "a", "SHA512", "Name of hashing algorithm to be used")
	unsealCmd.Flags().StringVarP(&common.Unseal.TargetRegistry, "target-registry", "r", common.LocalRegistry, "URL of the target registry to import container images; 'local' imports them locally")

	return rootCmd.Execute()
}

// readConfiguration searches for the latest configuration file and reads the contents.
// The contents are parsed as a slice of PackageContent from a JSON or YAML file.
func readConfiguration(fileName string) error {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	var contents shared.ArchiveContents
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".json":
		err = json.Unmarshal(data, &contents)
		break
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &contents)
		break
	default:
		err = fmt.Errorf("invalid file type: %s", filepath.Ext(fileName))
	}
	if err != nil {
		return err
	}
	if contents.Files != nil {
		common.Seal.Files = contents.Files
	}
	if contents.Images != nil {
		common.Seal.Images = make([]*shared.ContainerImage, len(contents.Images))
		for i := 0; i < len(contents.Images); i++ {
			common.Seal.Images[i] = common.ParseContainerImage(contents.Images[i])
		}
	}
	return nil
}
