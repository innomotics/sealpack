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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/apex/log"
	jsonHandler "github.com/apex/log/handlers/json"
	"os"
	"sealpack/common"
)

// main is the central entrypoint for sealpack.
func main() {
	log.SetHandler(jsonHandler.Default)
	// Parse CLI params and config
	// Internally starts execution from cobra
	check(ParseCommands())
}

// sealCommand is the combined command for sealing
func sealCommand() error {
	var err error
	// 1. Create envelope for the resulting file
	envelope := common.Envelope{
		HashAlgorithm:   common.GetHashAlgorithm(common.Seal.HashingAlgorithm),
		CompressionAlgo: common.GetCompressionAlgoIndex(common.Seal.CompressionAlgorithm),
	}

	// 2. Prepare TARget (pun intended) and add files and signatures
	log.Debug("seal: Bundling WriteArchive")
	arc := common.CreateArchiveWriter(common.Seal.Public, envelope.CompressionAlgo)
	signatures := common.NewSignatureList(common.Seal.HashingAlgorithm)
	if err = arc.AddContents(signatures); err != nil {
		return err
	}
	_ = common.CleanupImages() // Ignore: may not exist if no images have been stored

	// 3. Add TOC and sign it
	log.Debug("seal: adding TOC")
	err = arc.AddToc(signatures)
	envelope.PayloadLen, err = arc.Finalize()
	if err != nil {
		return fmt.Errorf("seal: failed finalizing archive: %v", err)
	}

	// 4. Encrypt keys
	log.Debugf("seal: encrypting %d keys", len(common.Seal.RecipientPubKeyPaths))
	// Now create encryption key and seal them for all recipients
	if err = addKeys(envelope, []byte(arc.EncryptionKey)); err != nil {
		return err
	}

	// 5. Write envelope
	log.Debug("seal: finalize output")
	out, err := common.NewOutputFile()
	if err != nil {
		return err
	}
	if err = envelope.WriteOutput(out, arc); err != nil {
		return err
	}
	if err = arc.Cleanup(); err != nil {
		return err
	}
	if err = common.CleanupFileWriter(out); err != nil {
		return err
	}
	log.Info("seal: successfully finished")
	return nil
}

// addKeys encrypts the symmetric key for every receiver and attaches them to the envelope
func addKeys(envelope common.Envelope, plainKey []byte) error {
	var err error
	envelope.ReceiverKeys = [][]byte{}
	if !common.Seal.Public {
		envelope.ReceiverKeys = make([][]byte, len(common.Seal.RecipientPubKeyPaths))
		for iKey, recipientPubKeyPath := range common.Seal.RecipientPubKeyPaths {
			var recPubKey *rsa.PublicKey
			if recPubKey, err = common.LoadPublicKey(recipientPubKeyPath); err != nil {
				return err
			}
			if envelope.ReceiverKeys[iKey], err = rsa.EncryptPKCS1v15(rand.Reader, recPubKey, plainKey); err != nil {
				return err
			}
			if len(envelope.ReceiverKeys[iKey]) != recPubKey.Size() {
				return fmt.Errorf("key size must be %d bits", recPubKey.Size())
			}
		}
	}
	return nil
}

// inspectCommand is the central command for inspecting a potentially sealed file
func inspectCommand() error {
	raw, err := os.Open(common.SealedFile)
	if err != nil {
		return err
	}
	envelope, err := common.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	log.Info(envelope.String())
	return nil
}

// unsealCommand is the combined command for unsealing
func unsealCommand() error {
	log.Debug("unseal: open sealed file")
	raw, err := os.Open(common.SealedFile)
	if err != nil {
		return err
	}
	// Try to parse the envelope
	envelope, err := common.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	payload, err := envelope.GetPayload()
	if err != nil {
		return err
	}
	archive, err := common.OpenArchiveReader(payload, envelope.CompressionAlgo)
	if err != nil {
		return err
	}
	log.Debug("unseal: read contents from archive")
	err = archive.Unpack()
	if err != nil {
		return err
	}
	log.Info("unseal: finished unsealing")
	return nil
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
