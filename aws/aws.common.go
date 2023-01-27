package aws

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
