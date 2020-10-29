package main

import (
	"fmt"
	"github.com/aidansteele/freedumb"
	"github.com/mdlayher/vsock"
	"io"
	"net"
)

func relayProxiedTraffic() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", freedumb.HttpProxyPort))
	if err != nil {
		panic(err)
	}

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			hostConn, err := vsock.Dial(vsock.Host, freedumb.HttpProxyPort)
			if err != nil {
				panic(err)
			}

			go io.Copy(clientConn, hostConn)
			io.Copy(hostConn, clientConn)
		}()
	}
}
