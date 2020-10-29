package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aidansteele/freedumb"
	"github.com/aidansteele/freedumb/nsm"
	"github.com/aws/aws-sdk-go/private/protocol"
	"github.com/mdlayher/vsock"
	"github.com/pkg/errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve-credentials" {
		serveCreds()
		return
	}

	// seed /dev/random
	randbytes := nsm.GetRandomBytes(1024)
	err := reseedRNG(randbytes)
	if err != nil {
		panic(err)
	}

	// setup loopback networking
	cmd := exec.Command("/bin/sh", "-c", "ifconfig lo 127.0.0.1 && ip route add 127.0.0.0/8 dev lo")
	err = cmd.Run()
	if err != nil {
		panic(err)
	}

	suffix := protocol.GetIdempotencyToken()
	payload, err := initializationPayload()
	if err != nil {
	    panic(err)
	}

	os.Setenv("http_proxy", fmt.Sprintf("http://127.0.0.1:%d", freedumb.HttpProxyPort))

	err = startCredentialServerProcess(suffix, payload)
	if err != nil {
	    panic(err)
	}

	err = execApplicationProcess(suffix, payload)
	if err != nil {
	    panic(err)
	}
}

func execApplicationProcess(suffix string, payload *freedumb.InitializationPayload) error {
	credUrl := fmt.Sprintf("http://localhost:%d/credentials/%s?roleArn=%s", freedumb.CredentialServerPort, suffix, url.QueryEscape(payload.RoleArn))
	os.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", credUrl)
	os.Setenv("AWS_REGION", payload.Region)

	commandName := os.Args[1]
	commandPath, err := exec.LookPath(commandName)
	if err != nil {
	   return errors.WithStack(err)
	}

	err = syscall.Exec(commandPath, os.Args[1:], os.Environ())
	if err != nil {
	   return errors.WithStack(err)
	}

	return nil
}

func startCredentialServerProcess(suffix string, payload *freedumb.InitializationPayload) error {
	exe, err := os.Executable()
	if err != nil {
		return errors.WithStack(err)
	}

	pj, _ := json.Marshal(payload)

	cmd := exec.Command(exe, "serve-credentials", suffix, string(pj))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func initializationPayload() (*freedumb.InitializationPayload, error) {
	conn, err := vsock.Dial(vsock.Host, freedumb.InitializationPayloadPort)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	defer conn.Close()

	payloadJson := &bytes.Buffer{}
	_, err = io.Copy(payloadJson, conn)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	payload := &freedumb.InitializationPayload{}
	err = json.Unmarshal(payloadJson.Bytes(), &payload)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return payload, nil
}
