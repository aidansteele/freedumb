package main

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	"fmt"
	"github.com/aidansteele/freedumb"
	"github.com/aidansteele/freedumb/nsm"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

func serveCreds() {
	go relayProxiedTraffic()

	suffix, payloadstr := os.Args[2], os.Args[3]
	path := "/credentials/" + suffix

	payload := &freedumb.InitializationPayload{}
	err := json.Unmarshal([]byte(payloadstr), &payload)
	if err != nil {
		panic(err)
	}

	cs := &credentialServer{initialization: payload}

	http.HandleFunc(path, cs.handle)

	addr := fmt.Sprintf(":%d", freedumb.CredentialServerPort)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		panic(err)
	}
}

type credentialServer struct {
	initialization *freedumb.InitializationPayload
}

func (s *credentialServer) handle(w http.ResponseWriter, r *http.Request) {
	req := freedumb.AssumeRoleRequest{
		InstanceId:         s.initialization.InstanceId,
		InstanceIamRoleArn: s.initialization.InstanceIamRoleArn,
		RequestedRoleArn:   r.URL.Query().Get("roleArn"),
	}

	reqj, _ := json.Marshal(req)

	identity, err := age.GenerateX25519Identity()
	if err != nil {
	    panic(err)
	}

	doc := nsm.GetDocument([]byte(identity.Recipient().String()), reqj, nil)

	resp, err := http.Post(s.initialization.IdpUrl, "application/octet-stream", bytes.NewReader(doc))
	if err != nil {
		panic(err)
	}

	encr, err := age.Decrypt(resp.Body, identity)
	if err != nil {
	    panic(err)
	}

	respBody, err := ioutil.ReadAll(encr)
	if err != nil {
	    panic(err)
	}

	idpResponse := freedumb.AssumeRoleResponse{}
	err = json.Unmarshal(respBody, &idpResponse)
	if err != nil {
		panic(err)
	}

	credResponse := credentialsResponse{
		AccessKeyId:     idpResponse.AccessKeyId,
		SecretAccessKey: idpResponse.SecretAccessKey,
		Token:           idpResponse.Token,
		Expiration:      idpResponse.Expiration,
	}

	j, _ := json.Marshal(credResponse)
	w.Write(j)
}

type credentialsResponse struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}
