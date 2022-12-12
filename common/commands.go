package common

import (
	"github.com/spf13/cobra"
)

type SealConfig struct {
	PubkeyPath string
	Files      []string
}

type UnsealConfig struct {
	PrivkeyPath string
	TargetPath  string
}

var (
	// rootCmd describes the main cobra.Command
	rootCmd = &cobra.Command{
		Use:  "sealpack",
		Long: "A cryptographic sealing packager",
	}
	// sealCmd describes the `trigger` subcommand as cobra.Command
	sealCmd = &cobra.Command{
		Use:   "seal",
		Short: "Triggers packaging on USB insert",
		Long:  "Triggers the package creation based on a udev systemd trigger once instead of polling USB devices",
	}
	// unsealCmd describes the `unpack` subcommand as cobra.Command
	unsealCmd = &cobra.Command{
		Use:   "unseal [path to IPC.iqlogs file]",
		Short: "Unpacks a sealed archive",
		Long:  "Unpacks a sealed archive if the provided private key is valid",
		Args:  cobra.ExactArgs(1),
	}

	Seal   *SealConfig
	Unseal *UnsealConfig
)

// ParseCommands is configuring all cobra commands and execute them
func ParseCommands() error {
	Seal = &SealConfig{}
	Unseal := &UnsealConfig{}

	rootCmd.Commands()

	rootCmd.AddCommand(sealCmd)
	sealCmd.Flags().StringVarP(&Seal.PubkeyPath, "pubkey", "p", "", "Path to the public key")
	sealCmd.Flags().StringArrayVarP(&Seal.Files, "file", "f", make([]string, 0), "Path to the config file")

	rootCmd.AddCommand(unsealCmd)
	unsealCmd.Flags().StringVarP(&Unseal.PrivkeyPath, "privkey", "p", "", "Path to the private key")
	unsealCmd.Flags().StringVarP(&Unseal.TargetPath, "target", "t", ".", "Target path to unpack the contents to")

	return rootCmd.Execute()
}
