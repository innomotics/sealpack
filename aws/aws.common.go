package aws

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"log"
)

var sess *session.Session

func verifyAwsSession() {
	if sess == nil {
		var err error
		sess, err = session.NewSession()
		if err != nil {
			log.Fatal(err)
		}
	}
}
