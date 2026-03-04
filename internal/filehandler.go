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
	"os"
)

var stdout = os.Stdout

// NewOutputFile creates a new output file depending on the type of output target
func NewOutputFile(output string) (*os.File, error) {
	if output == "-" {
		return stdout, nil
	}
	return os.Create(output)
}
