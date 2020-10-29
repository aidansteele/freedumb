package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

func main() {
	sess, err := session.NewSession()
	if err != nil {
		panic(err)
	}

	api := sts.New(sess)
	stsresp, err := api.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
	    panic(err)
	}

	fmt.Printf("Hello, world! My name is %s\n", *stsresp.Arn)
}
