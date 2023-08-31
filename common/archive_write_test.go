package common

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
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

// This file contains unit tests for the WriteArchive

func Test_CreateWriteFinalizeArchive(t *testing.T) {
	// Create Archive creates buffer and writers
	arc := CreateArchiveWriter(true, 0)
	assert.NotNil(t, arc.compressWriter)
	assert.NotNil(t, arc.tarWriter)
	assert.NotNil(t, arc.outFile)
	assert.Nil(t, arc.encryptWriter)

	// Add 2 files with 1000 bytes each
	contents := make([]byte, 1000)
	for i := 0; i < 1000; i++ {
		contents = append(contents, 'A')
	}
	assert.NoError(t, arc.AddToArchive("foo", contents))
	assert.NoError(t, arc.AddToArchive("bar", contents))

	// Finalize
	b, err := arc.Finalize()
	assert.NoError(t, err)
	// ~130 bytes compressed
	assert.True(t, b >= 100 && b <= 150)
}

func TestEnvelope_WriteHeader(t *testing.T) {
	tests := []struct {
		name    string
		buf     *bytes.Buffer
		fields  *Envelope
		wantW   string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Valid simple envelope",
			buf:  &bytes.Buffer{},
			fields: &Envelope{
				PayloadLen:      1337,
				CompressionAlgo: 2,
				HashAlgorithm:   12,
			},
			wantW:   "\xDBIPC\x4C\x39\x05\x00\x00\x00\x00\x00\x00",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fields.WriteHeader(tt.buf)
			if !tt.wantErr(t, err, fmt.Sprintf("WriteHeader(%v)", tt.buf)) {
				return
			}
			assert.Equalf(t, tt.wantW, tt.buf.String(), "WriteHeader(%v)", tt.buf)
		})
	}
}

func TestEnvelope_WriteKeys(t *testing.T) {
	tests := []struct {
		name    string
		fields  *Envelope
		wantW   string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Valid public envelope",
			fields: &Envelope{
				ReceiverKeys: make([][]byte, 0),
			},
			wantW:   "",
			wantErr: assert.NoError,
		},
		{
			name: "Valid envelope with 2 Blocks size",
			fields: &Envelope{
				ReceiverKeys: [][]byte{[]byte("1234567812345678")},
			},
			wantW:   "\x021234567812345678",
			wantErr: assert.NoError,
		},
		{
			name: "Valid envelope with invalid blocks size",
			fields: &Envelope{
				ReceiverKeys: [][]byte{[]byte("123456781234")},
			},
			wantW:   "",
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := tt.fields.WriteKeys(w)
			if !tt.wantErr(t, err, fmt.Sprintf("WriteKeys(%v)", w)) {
				return
			}
			assert.Equalf(t, tt.wantW, w.String(), "WriteKeys(%v)", w)
		})
	}
}

func TestCreateArchiveWriter_NonPublic_Write_Cleanup(t *testing.T) {
	// Create Archive writer with receivers and zlib compression
	arc := CreateArchiveWriter(false, 1)
	assert.NotNil(t, arc.compressWriter)
	assert.NotNil(t, arc.encryptWriter)
	assert.NotNil(t, arc.tarWriter)
	assert.NotNil(t, arc.outFile)

	// Write some file to the archive
	f, err := os.CreateTemp("../test", "tmp")
	assert.NoError(t, err)
	defer os.Remove(f.Name())
	contents := make([]byte, 1000)
	for i := 0; i < 1000; i++ {
		contents = append(contents, 'A')
	}
	_, err = f.Write(contents)
	assert.NoError(t, err)
	_, err = f.Seek(0, 0)
	assert.NoError(t, err)
	assert.NoError(t, arc.WriteToArchive("foo", f))

	// And Cleanup
	assert.NoError(t, arc.Cleanup())
}

func TestAddContents(t *testing.T) {
	// Create Archive creates buffer and writers (flate compression)
	arc := CreateArchiveWriter(true, 3)
	assert.NotNil(t, arc.compressWriter)
	assert.NotNil(t, arc.tarWriter)
	assert.NotNil(t, arc.outFile)
	assert.Nil(t, arc.encryptWriter)

	// Add File
	f, err := os.CreateTemp("../test", "tmp")
	assert.NoError(t, err)
	defer os.Remove(f.Name())
	contents := make([]byte, 1000)
	for i := 0; i < 1000; i++ {
		contents = append(contents, 'A')
	}
	_, err = f.Write(contents)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())

	// Add Images and Files
	Seal = &SealConfig{
		PrivKeyPath: "../test/private.pem",
		Files:       []string{f.Name()},
	}
	Seal.Images = []*ContainerImage{
		ParseContainerImage("alpine:latest"),
		ParseContainerImage("alpine:3.16"),
		ParseContainerImage("alpine:3.17"),
	}

	// Add Signatures and finally add contents
	sig := NewSignatureList("SHA256")
	assert.NoError(t, arc.AddContents(sig))

	// Add TOC from signatures
	assert.NoError(t, arc.AddToc(sig))

	size, err := arc.Finalize()
	assert.NoError(t, err)
	assert.Greater(t, size, int64(1000000))
}

func TestAddTocNoKey(t *testing.T) {
	// Create Archive creates buffer and writers (flate compression)
	arc := CreateArchiveWriter(true, 3)
	assert.NotNil(t, arc.compressWriter)
	assert.NotNil(t, arc.tarWriter)
	assert.NotNil(t, arc.outFile)
	assert.Nil(t, arc.encryptWriter)

	Seal = &SealConfig{
		PrivKeyPath: "../test/foo.bar",
	}

	sig := NewSignatureList("SHA256")
	assert.NoError(t, arc.AddContents(sig))
	assert.ErrorContains(t, arc.AddToc(sig), "seal: could not create signer: open ../test/foo.bar: no such file or directory")
}

// Test_WriteOutput only tests the successful default case
func Test_WriteOutput(t *testing.T) {
	// Create Archive creates buffer and writers
	arc := CreateArchiveWriter(true, 0)
	assert.NotNil(t, arc.compressWriter)
	assert.NotNil(t, arc.tarWriter)
	assert.NotNil(t, arc.outFile)
	assert.Nil(t, arc.encryptWriter)

	assert.NoError(t, arc.AddToArchive("foo", []byte("foo")))

	envel := Envelope{
		CompressionAlgo: 0,
	}
	f, err := os.OpenFile("../test/tmp.out", os.O_CREATE|os.O_RDWR, 0777)
	defer os.Remove(f.Name())
	assert.NoError(t, err)
	assert.NoError(t, envel.WriteOutput(f, arc))
	assert.FileExists(t, "../test/tmp.out")
}
