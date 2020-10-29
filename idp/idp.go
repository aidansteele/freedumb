package main

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	"fmt"
	"github.com/aidansteele/freedumb"
	"github.com/aidansteele/freedumb/attestation"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := handle(w, r)
		if err != nil {
			fmt.Printf("err: %+v\n", err)
			panic(err)
		}
	})

	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		panic(err)
	}
}

func handle(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	rawDoc, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return errors.WithStack(err)
	}

	doc, err := attestation.ParseAttestationDocument(rawDoc)
	if err != nil {
		return errors.WithStack(err)
	}

	assumeRequest := freedumb.AssumeRoleRequest{}
	err = json.Unmarshal(doc.UserData, &assumeRequest)
	if err != nil {
		return errors.WithStack(err)
	}

	validInstanceRole := doc.VerifyPCR(attestation.PCR3InstanceIamRoleArnHash, assumeRequest.InstanceIamRoleArn)
	validInstanceId := doc.VerifyPCR(attestation.PCR4InstanceIdHash, assumeRequest.InstanceId)
	if !validInstanceId || !validInstanceRole {
		return errors.New("invalid instance role arn or instance id")
	}

	sess, err := session.NewSession()
	if err != nil {
		return errors.WithStack(err)
	}

	roleArn, _ := arn.Parse(assumeRequest.InstanceIamRoleArn)

	tagMap := map[string]string{
		"enclave:enclave-id":        doc.EnclaveId,
		"enclave:instance-id":       doc.InstanceId,
		"enclave:account-id":        roleArn.AccountID,
		"enclave:instance-role-arn": assumeRequest.InstanceIamRoleArn,
	}

	tags := []*sts.Tag{}
	for k, v := range tagMap {
		tags = append(tags, &sts.Tag{Key: aws.String(k), Value: aws.String(v)})
	}

	api := sts.New(sess)
	stsResp, err := api.AssumeRoleWithContext(ctx, &sts.AssumeRoleInput{
		RoleArn:         &assumeRequest.RequestedRoleArn,
		RoleSessionName: aws.String(fmt.Sprintf("%s-%s", doc.InstanceId, doc.EnclaveId)),
		Tags:            tags,
	})
	if err != nil {
		return errors.WithStack(err)
	}

	c := stsResp.Credentials
	assumeResponse := freedumb.AssumeRoleResponse{
		AccessKeyId:     *c.AccessKeyId,
		SecretAccessKey: *c.SecretAccessKey,
		Token:           *c.SessionToken,
		Expiration:      *c.Expiration,
	}

	responseJson, _ := json.Marshal(assumeResponse)

	out := &bytes.Buffer{}
	encw, err := age.Encrypt(out, doc.PublicKey)
	if err != nil {
	    panic(err)
	}

	_, err = encw.Write(responseJson)
	if err != nil {
	    panic(err)
	}

	err = encw.Close()
	if err != nil {
	    panic(err)
	}

	w.Write(out.Bytes())
	return nil
}
