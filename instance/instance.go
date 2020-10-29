package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aidansteele/freedumb"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mdlayher/vsock"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	"io"
	"os"
	"os/exec"
	"strings"
)

func main() {
	ctx := context.Background()
	g, ctx := errgroup.WithContext(ctx)

	idpUrl := ""
	pflag.StringVar(&idpUrl, "idp-url", "", "")

	roleArn := ""
	pflag.StringVar(&roleArn, "role-arn", "", "")

	pflag.Parse()

	g.Go(func() error {
		return serveInitializationPayload(ctx, idpUrl, roleArn)
	})

	g.Go(func() error {
		return proxy(ctx)
	})

	pr, pw := io.Pipe()

	args := append([]string{"run-enclave"}, pflag.Args()...)
	cmd := exec.CommandContext(ctx, "nitro-cli", args...)
	cmd.Stdout = io.MultiWriter(pw, os.Stdout)
	cmd.Stderr = io.MultiWriter(pw, os.Stderr)
	g.Go(cmd.Run)

	g.Go(func() error {
		scan := bufio.NewScanner(pr)
		buf := &bytes.Buffer{}
		readingJson := false

		for scan.Scan() {
			line := scan.Text()
			if strings.HasPrefix(line, "Started enclave with") {
				readingJson = true
			} else if readingJson {
				buf.Write(scan.Bytes())
			}

			if line == "}" {
				break
			}
		}

		m := map[string]interface{}{}
		err := json.Unmarshal(buf.Bytes(), &m)
		if err != nil {
			return errors.WithStack(err)
		}

		enclaveId := m["EnclaveID"].(string)
		cmd := exec.CommandContext(ctx, "nitro-cli", "console", "--enclave-id", enclaveId)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		return errors.WithStack(err)
	})

	err := g.Wait()
	if err != nil {
		panic(err)
	}
}

func serveInitializationPayload(ctx context.Context, idpUrl, roleArn string) error {
	listener, err := vsock.Listen(freedumb.InitializationPayloadPort)
	if err != nil {
		return errors.WithStack(err)
	}

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return errors.WithStack(err)
		}

		go func() {
			defer conn.Close()

			payloadJson, err := initializationPayload(ctx, idpUrl, roleArn)
			if err != nil {
				panic(err)
			}

			_, err = io.Copy(conn, bytes.NewReader(payloadJson))
			if err != nil {
				panic(err)
			}
		}()
	}
}

func initializationPayload(ctx context.Context, idpUrl, roleArn string) ([]byte, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	meta := ec2metadata.New(sess)
	identity, err := meta.GetInstanceIdentityDocumentWithContext(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := meta.GetMetadataWithContext(ctx, "iam/security-credentials/")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	names := strings.Split(resp, "\n")
	instanceRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", identity.AccountID, names[0])

	initializationPayload := freedumb.InitializationPayload{
		InstanceId:         identity.InstanceID,
		InstanceIamRoleArn: instanceRoleArn,
		Region:             identity.Region,
		IdpUrl:             idpUrl,
		RoleArn:            roleArn,
	}

	payloadJson, _ := json.Marshal(initializationPayload)
	return payloadJson, err
}
