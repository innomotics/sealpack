package internal

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
	"fmt"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/stretchr/testify/assert"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func sp(s string) *string {
	return &s
}

func TestParseEnvelopeInvalid(t *testing.T) {

	tests := []struct {
		name    string
		args    io.ReadSeeker
		wantErr *string
	}{
		{
			"Arbitrary string",
			bytes.NewReader([]byte("Pink fluffy unicorns dancing on rainbows.")),
			sp("not a valid sealpack file"),
		},
		{
			"Empty string",
			bytes.NewReader([]byte{}),
			sp("EOF"),
		},
		{
			"Only magic bytes",
			bytes.NewReader([]byte("\xDBIPC")),
			sp("EOF"),
		},
		{
			"No payload length",
			bytes.NewReader([]byte("\xDBIPC\x07")),
			sp("EOF"),
		},
		{
			"Too little payload length",
			bytes.NewReader([]byte("\xDBIPC\x07\x00\x00\x00\x00\x07")),
			sp("EOF"),
		},
		{
			"Too little payload for provided length",
			bytes.NewReader([]byte("\xDBIPC\x07\x07\x00\x00\x00\x00\x00\x00\x00Foo")),
			sp("EOF"),
		},
		{
			"No key where it should have one",
			bytes.NewReader([]byte("\xDBIPC\x07\x03\x00\x00\x00\x00\x00\x00\x00Foo\x01")),
			sp("EOF"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEnvelope(tt.args)
			assert.Nil(t, got)
			assert.ErrorContains(t, err, *tt.wantErr)
		})
	}
}

func TestGetCompressionAlgoName(t *testing.T) {
	tests := []struct {
		name string
		idx  uint8
		want string
	}{
		{"GZIP", 0, "gzip"},
		{"ZLIB", 1, "zlib"},
		{"ZIP", 2, "zip"},
		{"FLATE", 3, "flate"},
		{"INVALID", 4, "gzip"},
		{"INVALID", 99, "gzip"},
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, GetCompressionAlgoName(tt.idx), "GetCompressionAlgoName(%v)", tt.idx)
			if int(tt.idx) >= len(compressionAlgorithms) {
				assert.Contains(t, buf.String(), fmt.Sprintf("Invalid algorithm index '%d', defaulting to 'gzip'", tt.idx))
			}
		})
	}
}

func TestGetCompressionAlgoIndex(t *testing.T) {
	tests := []struct {
		name string
		idx  uint8
		want string
	}{
		{"GZIP", 0, "gzip"},
		{"ZLIB", 1, "zlib"},
		{"ZIP", 2, "zip"},
		{"FLATE", 3, "flate"},
		{"INVALID", 0, "dump"},
		{"INVALID", 0, ""},
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	for ti, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.idx, GetCompressionAlgoIndex(tt.want), "GetCompressionAlgoIndex(%v)", tt.want)
			if ti >= len(compressionAlgorithms) {
				assert.Contains(t, buf.String(), fmt.Sprintf("Invalid algorithm '%s', defaulting to 'gzip'", tt.want))
			}
		})
	}
}

// Tests for Archive Reader

func TestOpenArchiveReader(t *testing.T) {
	// Arrange
	algo := "SHA512"
	sig := NewSignatureList(algo)
	arc := CreateArchiveWriter(true, 0)
	assert.NoError(t, arc.AddToArchive("path/to/foo", []byte("Hold your breath and count to 10.")))
	assert.NoError(t, sig.AddFile("path/to/foo", []byte("Hold your breath and count to 10.")))
	assert.NoError(t, arc.AddToc("../test/private.pem", sig))
	b, err := arc.Finalize()
	assert.NoError(t, err)
	assert.True(t, b > 10)

	// Act
	f, err := os.Open(arc.outFile.Name())
	assert.NoError(t, err)
	ra, err := OpenArchiveReader(f, 0)
	assert.NoError(t, err)
	assert.NoError(t, ra.Unpack("../test/public.pem", algo, "", "", ""))
}

func TestReadArchive_InitializeCompression(t *testing.T) {
	type args struct {
		r               io.Reader
		compressionAlgo uint8
	}
	gzFile, _ := os.CreateTemp("../test", "_*.gz")
	defer os.Remove(gzFile.Name())
	_, _ = gzip.NewWriter(gzFile).Write([]byte("FooBarTrololol"))
	gzFile.Seek(0, 0)
	zlibFile, _ := os.CreateTemp("../test", "_*.zlib")
	defer os.Remove(zlibFile.Name())
	_, _ = zlib.NewWriter(zlibFile).Write([]byte("FooBarTrololol"))
	zlibFile.Seek(0, 0)
	flateFile, _ := os.CreateTemp("../test", "_*.flate")
	defer os.Remove(flateFile.Name())
	w, _ := flate.NewWriter(flateFile, 0)
	_, _ = w.Write([]byte("FooBarTrololol"))
	flateFile.Seek(0, 0)
	tests := []struct {
		name    string
		arc     *ReadArchive
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Test simple (gzip)",
			arc: &ReadArchive{
				reader: gzFile,
			},
			args: args{
				r:               gzFile,
				compressionAlgo: 0,
			},
			wantErr: assert.NoError,
		},
		{
			name: "Test zlib",
			arc: &ReadArchive{
				reader: zlibFile,
			},
			args: args{
				r:               zlibFile,
				compressionAlgo: 1,
			},
			wantErr: assert.NoError,
		},
		{
			name: "Test zip (defaults to gzip)",
			arc: &ReadArchive{
				reader: gzFile,
			},
			args: args{
				r:               gzFile,
				compressionAlgo: 2,
			},
			wantErr: assert.NoError,
		},
		{
			name: "Test flate",
			arc: &ReadArchive{
				reader: flateFile,
			},
			args: args{
				r:               flateFile,
				compressionAlgo: 3,
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, tt.arc.InitializeCompression(tt.args.r, tt.args.compressionAlgo), fmt.Sprintf("InitializeCompression(%v, %v)", tt.args.r, tt.args.compressionAlgo))
		})
	}
}
