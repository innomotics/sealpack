package main

/*
 * Sealpack
 *
 * Copyright (c) Innomotics GmbH, 2023
 *
 * Authors:
 *  Mathias Haimerl <mathias.haimerl@siemens.com>
 *
 * This work is licensed under the terms of the Apache 2.0 license.
 * See the LICENSE.txt file in the top-level directory.
 *
 * SPDX-License-Identifier:	Apache-2.0
 */

import (
	"context"
	"github.com/apex/log"
	jsonHandler "github.com/apex/log/handlers/json"
	"github.com/innomotics/sealpack"
	"github.com/spf13/cobra"
	"os"
)

type CommandConfig struct {
	Seal    *sealpack.SealConfig
	Unseal  *sealpack.UnsealConfig
	Inspect string
}

var (
	// logLevel defines the verbosity of logging
	logLevel string
	// rootCmd describes the main cobra.Command
	rootCmd = &cobra.Command{
		Use:  "sealpack",
		Long: "A cryptographic sealing packager",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			l, err := log.ParseLevel(logLevel)
			if err != nil {
				return err
			}
			log.SetLevel(l)
			return err
		},
	}

	// sealCmd describes the `trigger` subcommand as cobra.Command
	sealCmd = &cobra.Command{
		Use:   "seal",
		Short: "Create sealed archive",
		Long:  "Create a sealed package",
		Run: func(cmd *cobra.Command, args []string) {
			check(sealpack.Seal(cmd.Context().Value("config").(*CommandConfig).Seal))
		},
	}

	// inspectCmd describes the `inspect` subcommand as cobra.Command
	inspectCmd = &cobra.Command{
		Use:   "inspect",
		Short: "Inspects a sealed archive",
		Long:  "Inspects a sealed archive and allows for identifying any errors",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			check(sealpack.Inspect(args[0]))
		},
	}
	// unsealCmd describes the `unpack` subcommand as cobra.Command
	unsealCmd = &cobra.Command{
		Use:   "unseal",
		Short: "Unpacks a sealed archive",
		Long:  "Unpacks a sealed archive if the provided private key is valid",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Pass filename as first argument
			check(sealpack.Unseal(args[0], cmd.Context().Value("config").(*CommandConfig).Unseal))
		},
	}
)

// ParseCommands is configuring all cobra commands and execute them
func ParseCommands() error {
	conf := &CommandConfig{
		Seal:    &sealpack.SealConfig{},
		Unseal:  &sealpack.UnsealConfig{},
		Inspect: "",
	}

	rootCmd.Commands()
	rootCmd.PersistentFlags().StringVarP(&logLevel, "loglevel", "l", "info", "Logging verbosity. Allowed values are 'debug', 'info', 'warning', 'error', 'fatal'. Default is 'info'")

	rootCmd.AddCommand(sealCmd)
	sealCmd.Flags().StringVarP(&conf.Seal.PrivKeyPath, "privkey", "p", "", "Path to the private signing key. AWS KMS keys can be used with awskms:/// prefix")
	sealCmd.Flags().StringSliceVarP(&conf.Seal.RecipientPubKeyPaths, "recipient-pubkey", "r", make([]string, 0), "Paths of recipients' public keys. AWS KMS keys can be used with awskms:/// prefix")
	sealCmd.Flags().StringVarP(&conf.Seal.Output, "output", "o", "", "Filename to store the result in")
	_ = sealCmd.MarkFlagRequired("privkey")
	_ = sealCmd.MarkFlagRequired("output")
	sealCmd.Flags().BoolVar(&conf.Seal.Public, "public", false, "Don't encrypt, contents are signed only and can be retrieved from any receiver")
	sealCmd.Flags().StringVarP(&conf.Seal.ContentFileName, "contents", "c", "", "Provide all contents as a central configurations file (supports JSON, YAML)")
	sealCmd.Flags().StringSliceVarP(&conf.Seal.Files, "file", "f", make([]string, 0), "Path to the files to be added")
	sealCmd.Flags().StringSliceVarP(&conf.Seal.ImageNames, "image", "i", make([]string, 0), "Name of container images to be added")
	sealCmd.Flags().StringVarP(&conf.Seal.HashingAlgorithm, "hashing-algorithm", "a", "SHA512", "Name of hashing algorithm to be used")
	sealCmd.Flags().StringVarP(&conf.Seal.CompressionAlgorithm, "compression-algorithm", "z", "gzip", "Name of compression algorithm to be used [gzip, zlib, zip, flate]")

	rootCmd.AddCommand(inspectCmd)

	rootCmd.AddCommand(unsealCmd)
	unsealCmd.Flags().StringVarP(&conf.Unseal.PrivKeyPath, "privkey", "p", "", "Private key of the receiver")
	unsealCmd.Flags().StringVarP(&conf.Unseal.SigningKeyPath, "signer-key", "s", "", "Public key of the signing entity")
	unsealCmd.Flags().StringVarP(&conf.Unseal.OutputPath, "output", "o", ".", "Output path to unpack the contents to")
	_ = sealCmd.MarkFlagRequired("signer-key")
	unsealCmd.Flags().StringVarP(&conf.Unseal.HashingAlgorithm, "hashing-algorithm", "a", "SHA512", "Name of hashing algorithm to be used")
	unsealCmd.Flags().StringVarP(&conf.Unseal.TargetRegistry, "target-registry", "r", "local", "URL of the target registry to import container images; 'local' imports them locally")
	unsealCmd.Flags().StringVarP(&conf.Unseal.Namespace, "namespace", "n", "default", "ContainerD namespace to import the images into")

	return rootCmd.ExecuteContext(context.WithValue(context.Background(), "config", conf))
}

// main is the central entrypoint for sealpack.
func main() {
	log.SetHandler(jsonHandler.Default)
	// Parse CLI params and config
	// Internally starts execution from cobra
	check(ParseCommands())
}

// check tests if an error is nil; if not, it logs the error and exits the program
func check(err error, plus ...string) {
	if err != nil {
		log.Error(err.Error())
		for _, e := range plus {
			log.Error(e)
		}
		os.Exit(1)
	}
}
