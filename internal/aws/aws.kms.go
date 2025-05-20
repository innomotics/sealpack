package aws

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
	"fmt"
	"github.com/apex/log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/sigstore/sigstore/pkg/signature"
	kmssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

/*********************
 * KMS En-/Decrypter *
 *********************/

// KMSCryptoClient is the container for the KMS Key
type KMSCryptoClient struct {
	KeyID      string
	kmsSession *kms.KMS
	pubKey     *kms.GetPublicKeyOutput
}

// getPubKey requests the public key from AWS
func (enc *KMSCryptoClient) getPubKey() (*kms.GetPublicKeyOutput, error) {
	var err error
	if enc.pubKey == nil {
		enc.pubKey, err = enc.kmsSession.GetPublicKey(&kms.GetPublicKeyInput{
			KeyId: aws.String(enc.KeyID),
		})
		if err != nil {
			return nil, err
		}
	}
	return enc.pubKey, nil
}

// CanEncrypt provides a bool if the key is able to en-/decrypt
func (enc *KMSCryptoClient) CanEncrypt() bool {
	pubKey, err := enc.getPubKey()
	if err != nil {
		return false
	}
	log.Debugf("%v\n", pubKey)
	return *pubKey.KeyUsage == kms.KeyUsageTypeEncryptDecrypt
}

// KeySize returns the key length in bytes
func (enc *KMSCryptoClient) KeySize() int {
	if pubKey, err := enc.getPubKey(); err == nil {
		switch *pubKey.KeySpec {
		case kms.KeySpecRsa2048:
			return 256
		case kms.KeySpecRsa3072:
			return 384
		case kms.KeySpecRsa4096:
			return 512
		}
	}
	return 0
}

// KMSEncrypter implements the Encrypter interface with KMS
type KMSEncrypter struct {
	KMSCryptoClient
}

// EncryptMessage using the KMS API
func (enc *KMSEncrypter) EncryptMessage(message []byte) ([]byte, error) {
	out, err := enc.kmsSession.Encrypt(&kms.EncryptInput{
		Plaintext:           message,
		EncryptionAlgorithm: aws.String(kms.EncryptionAlgorithmSpecRsaesOaepSha256),
		KeyId:               aws.String(enc.KeyID),
	})
	if err != nil {
		return nil, err
	}
	return out.CiphertextBlob, nil
}

// NewKMSEncrypter generatea a new KMSEncrypter instance
func NewKMSEncrypter(keyID string) (*KMSEncrypter, error) {
	verifyAwsSession()
	enc := &KMSEncrypter{
		KMSCryptoClient: KMSCryptoClient{
			KeyID:      keyID,
			kmsSession: kms.New(sess),
		},
	}
	if !enc.CanEncrypt() {
		return nil, fmt.Errorf("kms key '%s' cannot encrypt", keyID)
	}
	return enc, nil
}

// KMSDecrypter implements the Decrypter interface with KMS
type KMSDecrypter struct {
	KMSCryptoClient
}

// DecryptMessage decrypts a message using the KMS API
func (dec *KMSDecrypter) DecryptMessage(message []byte) ([]byte, error) {
	out, err := dec.kmsSession.Decrypt(&kms.DecryptInput{
		CiphertextBlob:      message,
		EncryptionAlgorithm: aws.String(kms.EncryptionAlgorithmSpecRsaesOaepSha256),
		KeyId:               aws.String(dec.KeyID),
	})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

// NewKMSDecrypter generates a new KMSDecrypter instance
func NewKMSDecrypter(keyID string) (*KMSDecrypter, error) {
	verifyAwsSession()
	dec := &KMSDecrypter{
		KMSCryptoClient: KMSCryptoClient{
			KeyID:      keyID,
			kmsSession: kms.New(sess),
		},
	}
	if !dec.CanEncrypt() {
		return nil, fmt.Errorf("kms key cannot decrypt")
	}
	return dec, nil
}

/***************
 * KMS Signing *
 ***************/

// CreateKmsSigner creates a signer instance from a KMS ARN
func CreateKmsSigner(uri string) (signature.Signer, error) {
	verifyAwsSession()
	return kmssigner.LoadSignerVerifier(context.Background(), uri)
}

// CreateKmsVerifier creates a verifier instance from a KMS ARN
func CreateKmsVerifier(uri string) (signature.Verifier, error) {
	verifyAwsSession()
	return kmssigner.LoadSignerVerifier(context.Background(), uri)
}
