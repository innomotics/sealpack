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
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_ParseCommands(t *testing.T) {
	testArgs := os.Args
	os.Args = []string{"sealpack", "--help"}
	assert.NoError(t, ParseCommands())
	os.Args = testArgs
}

func Test_RootCmd_SetLogLevel(t *testing.T) {
	tests := []struct {
		name          string
		logLevel      string
		expectedError string
		wants         int
	}{
		{"no log level provided", "", "invalid level", -1},
		{"invalid log level provided", "foo", "invalid level", -1},
		{"debug log level provided", "debug", "", 0},
		{"Uppercase log level provided", "DEBUG", "", 0},
		{"error log level provided", "ErRoR", "", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logLevel = tt.logLevel
			res := rootCmd.PersistentPreRunE(nil, []string{})
			if tt.expectedError == "" {
				assert.NoError(t, res)
				assert.Equal(t, log.Level(tt.wants), log.Log.(*log.Logger).Level)
			} else {
				assert.ErrorContains(t, res, tt.expectedError)
			}
		})
	}
}
