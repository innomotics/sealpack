package sealpack

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
	"fmt"
	"github.com/apex/log"
	"os"
	"sealpack/common"
)

// Seal is the combined command for sealing
func Seal(sealCfg *common.SealConfig) error {
	var err error

	// 0 Prepare sealing
	if err = prepareSealing(sealCfg); err != nil {
		log.Error(err.Error())
		return err
	}

	// 1. Create envelope for the resulting file
	envelope := common.Envelope{
		HashAlgorithm:   common.GetHashAlgorithm(sealCfg.HashingAlgorithm),
		CompressionAlgo: common.GetCompressionAlgoIndex(sealCfg.CompressionAlgorithm),
	}

	// 2. Prepare TARget (pun intended) and add files and signatures
	log.Debug("seal: Bundling WriteArchive")
	arc := common.CreateArchiveWriter(sealCfg.Public, envelope.CompressionAlgo)
	signatures := common.NewSignatureList(sealCfg.HashingAlgorithm)
	if err = arc.AddContents(sealCfg, signatures); err != nil {
		return err
	}
	_ = common.CleanupImages() // Ignore: may not exist if no images have been stored

	// 3. Add TOC and sign it
	log.Debug("seal: adding TOC")
	err = arc.AddToc(sealCfg, signatures)
	if err != nil {
		return fmt.Errorf("seal: failed adding TOC: %v", err)
	}
	envelope.PayloadLen, err = arc.Finalize()
	if err != nil {
		return fmt.Errorf("seal: failed finalizing archive: %v", err)
	}

	// 4. Encrypt keys
	log.Debugf("seal: encrypting %d keys", len(sealCfg.RecipientPubKeyPaths))
	// Now create encryption key and seal them for all recipients
	if !sealCfg.Public {
		if err = common.AddKeys(sealCfg, &envelope, []byte(arc.EncryptionKey)); err != nil {
			return err
		}
	}

	// 5. Write envelope
	log.Debug("seal: finalize output")
	out, err := common.NewOutputFile(sealCfg)
	if err != nil {
		return err
	}
	if err = envelope.WriteOutput(out, arc); err != nil {
		return err
	}
	if err = arc.Cleanup(); err != nil {
		return err
	}
	if err = common.CleanupFileWriter(sealCfg, out); err != nil {
		return err
	}
	log.Info("seal: successfully finished")
	return nil
}

// Inspect is the central command for inspecting a potentially sealed file
func Inspect(sealedFile string) error {
	raw, err := os.Open(sealedFile)
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

// Unseal is the combined command for unsealing
func Unseal(sealedFile string, config *common.UnsealConfig) error {
	log.Debug("unseal: open sealed file")
	raw, err := os.Open(sealedFile)
	if err != nil {
		return err
	}
	// Try to parse the envelope
	envelope, err := common.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	payload, err := envelope.GetPayload(config)
	if err != nil {
		return err
	}
	archive, err := common.OpenArchiveReader(payload, envelope.CompressionAlgo)
	if err != nil {
		return err
	}
	log.Debug("unseal: read contents from archive")
	err = archive.Unpack(config)
	if err != nil {
		return err
	}
	log.Info("unseal: finished unsealing")
	return nil
}

// prepareSealing reads the configuration if provided, converting container image formats, and checking some preconditions
func prepareSealing(sealCfg *common.SealConfig) error {
	if sealCfg.ContentFileName != "" {
		if err := common.ReadConfiguration(sealCfg.ContentFileName, sealCfg); err != nil {
			return fmt.Errorf("invalid configuration file provided")
		}
	}
	if len(sealCfg.ImageNames) > 0 {
		for _, img := range sealCfg.ImageNames {
			sealCfg.Images = append(sealCfg.Images, common.ParseContainerImage(img))
		}
	}
	// public option cannot be used with receiver keys
	if sealCfg.Public && len(sealCfg.RecipientPubKeyPaths) > 0 {
		return fmt.Errorf("cannot use -public with -recipient-pubkey (illogical error)")
	}
	return nil
}
