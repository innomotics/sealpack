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
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

/*
func TestGetContainerDSocket(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			"Default ContainerD Socket",
			"/run/containerd/containerd.sock",
			assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetContainerDSocket()
			if !tt.wantErr(t, err, fmt.Sprintf("GetContainerDSocket()")) {
				return
			}
			assert.Equalf(t, tt.want, got, "GetContainerDSocket()")
		})
	}
}
*/

func Test_SaveImageAndCleanup(t *testing.T) {
	ci := ParseContainerImage("alpine:3.17")
	assert.Equal(t, "docker.io", ci.Registry)
	assert.Equal(t, "alpine", ci.Name)
	assert.Equal(t, "3.17", ci.Tag)
	file, err := SaveImage(ci)
	assert.NoError(t, err)
	stat, err := file.Stat()
	assert.NoError(t, err)
	tmpFolder := filepath.Join(os.TempDir(), TmpFolderName)
	ls, err := os.ReadDir(tmpFolder)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ls))
	assert.Equal(t, ".images", ls[0].Name())
	assert.False(t, stat.IsDir())
	// alpine should be 3-4 MB
	assert.True(t, stat.Size() > 3000000 && stat.Size() < 4000000)
	assert.DirExists(t, tmpFolder)
	assert.FileExists(t, filepath.Join(tmpFolder, ".images", ci.Registry, stat.Name()))
	assert.NoError(t, CleanupImages())
	assert.NoDirExists(t, tmpFolder)
	assert.NoFileExists(t, filepath.Join(tmpFolder, ".images", ci.Registry, stat.Name()))
}

func Test_FullParseContainerImage(t *testing.T) {
	input := "registry.example.com/unit/group/project/someimage:sometag"
	result := ParseContainerImage(input)
	assert.Equal(t, "registry.example.com", result.Registry)
	assert.Equal(t, "unit/group/project/someimage", result.Name)
	assert.Equal(t, "sometag", result.Tag)
	assert.Equal(t, input, result.String())
	assert.Equal(t, filepath.Join(ContainerImagePrefix, input+OCISuffix), result.ToFileName())
}

func Test_ParseContainerImageMin(t *testing.T) {
	input := "foo"
	result := ParseContainerImage(input)
	assert.Equal(t, "docker.io", result.Registry)
	assert.Equal(t, "foo", result.Name)
	assert.Equal(t, "latest", result.Tag)
}

func TestRemoveAll(t *testing.T) {
	tagsList := tagList{}
	for _, s := range []string{"cr.example.com/foobar:latest", "cr.example.com/foobar:v1", "cr.example.com/fnord:latest"} {
		nt, _ := name.NewTag(s)
		tagsList = append(tagsList, &nt)
	}
	tests := []struct {
		name    string
		tags    []*name.Tag
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "Delete empty list of tags",
			tags:    make([]*name.Tag, 0),
			wantErr: assert.NoError,
		},
		/*
		   // Does not work: No permissions //
		   			{
		   				name:    "Delete a bunch of nonexistent tags",
		   				tags:    tagsList,
		   				wantErr: assert.NoError,
		   			},
		*/

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Unseal = &UnsealConfig{TargetRegistry: LocalRegistry}
			tt.wantErr(t, RemoveAll(tt.tags), fmt.Sprintf("RemoveAll(%v)", tt.tags))
		})
	}
}

func Test_contains(t *testing.T) {
	type args[Q comparable] struct {
		haystack []Q
		needle   Q
	}
	type testCase[Q comparable] struct {
		name string
		args args[Q]
		want bool
	}
	tests := []testCase[string]{
		{
			name: "Simple found start",
			args: args[string]{haystack: []string{"foo", "bar", "melon", "fnord"}, needle: "foo"},
			want: true,
		},
		{
			name: "Simple found end",
			args: args[string]{haystack: []string{"foo", "bar", "melon", "fnord"}, needle: "fnord"},
			want: true,
		},
		{
			name: "Simple found middle",
			args: args[string]{haystack: []string{"foo", "bar", "melon", "fnord"}, needle: "bar"},
			want: true,
		},
		{
			name: "Simple not found",
			args: args[string]{haystack: []string{"foo", "bar", "melon", "fnord"}, needle: "mel0n"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, contains(tt.args.haystack, tt.args.needle), "contains(%v, %v)", tt.args.haystack, tt.args.needle)
		})
	}
	iTests := []testCase[int]{
		{
			name: "Simple found start",
			args: args[int]{haystack: []int{42, 1337, -69, 0, 4711}, needle: 42},
			want: true,
		},
		{
			name: "Simple found end",
			args: args[int]{haystack: []int{42, 1337, -69, 0, 4711}, needle: 4711},
			want: true,
		},
		{
			name: "Simple found middle",
			args: args[int]{haystack: []int{42, 1337, -69, 0, 4711}, needle: -69},
			want: true,
		},
		{
			name: "Simple not found",
			args: args[int]{haystack: []int{42, 1337, -69, 0, 4711}, needle: 127},
			want: false,
		},
	}
	for _, tt := range iTests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, contains(tt.args.haystack, tt.args.needle), "contains(%v, %v)", tt.args.haystack, tt.args.needle)
		})
	}
}
