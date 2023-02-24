package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/linux"
	"github.com/spf13/cobra"
	"log"
	"os"
	"sealpack/common"
	"sealpack/shared"
	"strings"
	"time"
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

	testCmd = &cobra.Command{
		Use:   "test",
		Short: "Test something",
		Run: func(cmd *cobra.Command, args []string) {
			check(TestHashSequence())
		},
	}

	contents string
)

func TestHashSequence() error {
	timeStart := time.Now()
	tcti, err := linux.OpenDevice("/dev/tpm0")
	if err != nil {
		return err
	}
	tpm := tpm2.NewTPMContext(tcti)
	defer tpm.Close()
	alg := tpm2.HashAlgorithmSHA256

	seq, err := tpm.HashSequenceStart(nil, alg)
	if err != nil {
		return err
	}

	//h := alg.NewHash()
	maxBlockSize := tpm.GetInputBuffer()
	f, err := os.Open("/home/z003t8rs/Downloads/iqem-fix-swapfile-f26e54d-airgap.ipc")
	if err != nil {
		return err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	part := make([]byte, maxBlockSize)
	var count int
	var result tpm2.Digest
	for {
		if count, err = reader.Read(part); err != nil {
			break
		}

		_, noFurtherBytes := reader.Peek(1)
		if noFurtherBytes != nil {
			var validation *tpm2.TkHashcheck
			result, validation, err = tpm.SequenceComplete(seq, part[:count], tpm2.HandleOwner, nil)
			if err != nil {
				return err
			}
			if validation != nil {
				return fmt.Errorf("error on complete hash: %v", validation)
			}
		} else {
			// Still data available
			if err := tpm.SequenceUpdate(seq, part[:count], nil); err != nil {
				return err
			}
		}
	}
	fmt.Println(result)
	fmt.Println(time.Now().Sub(timeStart))
	return nil
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
	_ = sealCmd.MarkFlagRequired("output")
	sealCmd.Flags().BoolVar(&common.Seal.Public, "public", false, "Don't encrypt, contents are signed only and can be retrieved from any receiver")
	sealCmd.Flags().StringVarP(&contents, "contents", "c", "", "Provide all contents as a central configurations file")
	sealCmd.Flags().StringSliceVarP(&common.Seal.Files, "file", "f", make([]string, 0), "Path to the files to be added")
	sealCmd.Flags().StringSliceVarP(&common.Seal.ImageNames, "image", "i", make([]string, 0), "Name of container images to be added")
	sealCmd.Flags().StringVarP(&common.Seal.HashingAlgorithm, "hashing-algorithm", "a", "SHA512", "Name of hashing algorithm to be used")

	rootCmd.AddCommand(inspectCmd)

	rootCmd.AddCommand(unsealCmd)
	unsealCmd.Flags().StringVarP(&common.Unseal.PrivKeyPath, "privkey", "p", "", "Private key of the receiver")
	unsealCmd.Flags().StringVarP(&common.Unseal.SigningKeyPath, "signer-key", "s", "", "Public key of the signing entity")
	unsealCmd.Flags().StringVarP(&common.Unseal.OutputPath, "output", "o", "output", "Output path to unpack the contents to")
	_ = sealCmd.MarkFlagRequired("signer-key")
	unsealCmd.Flags().StringVarP(&common.Unseal.HashingAlgorithm, "hashing-algorithm", "a", "SHA512", "Name of hashing algorithm to be used")
	unsealCmd.Flags().StringVarP(&common.Unseal.TargetRegistry, "target-registry", "r", common.LocalRegistry, "URL of the target registry to import container images; 'local' imports them locally")

	rootCmd.AddCommand(testCmd)

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
