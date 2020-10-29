package main

import (
	"context"
	"github.com/aidansteele/freedumb"
	"github.com/elazarl/goproxy"
	"github.com/mdlayher/vsock"
	"github.com/pkg/errors"
	"net/http"
)

func proxy(ctx context.Context) error {
	proxy := goproxy.NewProxyHttpServer()

	listener, err := vsock.Listen(freedumb.HttpProxyPort)
	if err != nil {
		return errors.WithStack(err)
	}

	srv := &http.Server{Handler: proxy}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	err = srv.Serve(listener)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
