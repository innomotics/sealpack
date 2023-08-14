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
	"crypto"
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func Test_OpenArchive(t *testing.T) {
	// Arrange
	arc := CreateArchiveWriter(true, 0)
	assert.NoError(t, arc.AddToArchive("path/to/foo", []byte("Hold your breath and count to 10.")))
	b, err := arc.Finalize()
	assert.NoError(t, err)
	assert.True(t, b > 10)

	// Act
	f, err := os.Open(arc.outFile.Name())
	assert.NoError(t, err)
	data, err := io.ReadAll(f)
	assert.NoError(t, err)
	ra, err := OpenArchive(data, 0)
	assert.NoError(t, err)
	assert.NotNil(t, ra.compressReader)
	assert.NotNil(t, ra.TarReader)
	assert.NotNil(t, ra.reader)
	h, err := ra.TarReader.Next()
	assert.NoError(t, err)
	assert.Equal(t, "path/to/foo", h.Name)
	outFile := new(bytes.Buffer)
	_, err = io.Copy(outFile, ra.TarReader)
	assert.NoError(t, err)
	assert.Equal(t, []byte("Hold your breath and count to 10."), outFile.Bytes())
}

func Test_OpenArchiveNoArchive(t *testing.T) {
	ra, err := OpenArchive([]byte("This is not an archive!"), 0)
	assert.ErrorContains(t, err, "invalid header")
	assert.Nil(t, ra)
}

func Test_Envelope(t *testing.T) {
	envelope := &Envelope{
		HashAlgorithm: crypto.SHA256,
	}
	var err error
	assert.Equal(t, int64(0), envelope.PayloadLen)
	assert.Equal(t, crypto.SHA256, envelope.HashAlgorithm)
	assert.Equal(t, 0, len(envelope.ReceiverKeys))
	envelope.PayloadWriter, err = os.Create(filepath.Join("../test", "tmp.bin"))
	assert.NoError(t, err)
	envelope.ReceiverKeys = [][]byte{[]byte("fuyoooh!")}

	// Test string
	strs := strings.Split(envelope.String(), "\n")
	assert.Contains(t, strs[0], "is a sealed package")
	assert.Contains(t, strs[1], "0 Bytes")
	assert.Contains(t, strs[2], "SHA-256 (32 Bit)")
	assert.Contains(t, strs[3], "for 1 receivers")

	// Test envelope byte slice
	bts := envelope.ToBytes()
	payloadLen := make([]byte, 9)
	payloadLen[0] = 5
	binary.LittleEndian.PutUint64(payloadLen[1:], uint64(envelope.PayloadLen))
	assert.Equal(t, append([]byte(EnvelopeMagicBytes), payloadLen...), bts[:13])
	assert.Equal(t, []byte("fuyoooh!"), bts[len(bts)-8:])

	f, err := os.CreateTemp("", "")
	defer assert.NoError(t, err)
	_, err = f.Write(bts)
	assert.NoError(t, err)
	_, err = f.Seek(0, 0)
	assert.NoError(t, err)

	// ParesEnvelope
	env, err := ParseEnvelope(f)
	assert.NoError(t, err)
	assert.EqualValues(t, envelope.HashAlgorithm, env.HashAlgorithm)
	assert.EqualValues(t, envelope.ReceiverKeys, env.ReceiverKeys)
}

func Test_EnvelopeInvalid(t *testing.T) {
	envelope, err := ParseEnvelope(bytes.NewReader([]byte("Pink fluffy unicorns dancing on rainbows.")))
	assert.ErrorContains(t, err, "not a valid sealpack file")
	assert.Nil(t, envelope)
}
