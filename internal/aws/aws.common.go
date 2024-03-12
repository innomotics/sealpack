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
	"github.com/aws/aws-sdk-go/aws/session"
	"log"
)

var sess *session.Session

// verifyAwsSession should be called to ensure an existing AWS session.
// If none is existing, a new one will be created.
func verifyAwsSession() {
	if sess == nil {
		var err error
		sess, err = session.NewSession()
		if err != nil {
			log.Fatal(err)
		}
	}
}
