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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ContainerImage(t *testing.T) {
	image := "cr.siemens.com/mathias.haimerl/sealpack:latest"
	ci := ParseContainerImage(image)
	assert.Equal(t,
		strings.Join(
			[]string{ContainerImagePrefix, ci.Registry, ci.Name + ":" + ci.Tag + OCISuffix},
			"/",
		),
		ci.ToFileName(),
	)
	assert.Equal(t, strings.Join(
		[]string{ci.Registry, ci.Name + ":" + ci.Tag},
		"/",
	),
		ci.String(),
	)
}

func TestNewOutputFile(t *testing.T) {
	tests := []struct {
		name        string
		want        string
		outputParam string
	}{
		{"Standard file", "/tmp/foo\\.bar", "/tmp/foo.bar"},
		{"Standard file", stdout.Name(), "-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewOutputFile(tt.outputParam)
			assert.NoError(t, err)
			assert.Regexp(t, tt.want, got.Name(), "NewOutputFile()")
		})
	}
}
