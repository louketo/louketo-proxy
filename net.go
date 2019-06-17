package main

/*
// deprecated upgrade: WebSocket connection upgrade is natively supported by stdlib reverse proxy

import (
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// isUpgradedConnection checks to see if the request is requesting
func isUpgradedConnection(req *http.Request) bool {
	return req.Header.Get(headerUpgrade) != ""
}

// transferBytes transfers bytes between the sink and source
func transferBytes(src io.Reader, dest io.Writer, wg *sync.WaitGroup) (int64, error) {
	defer wg.Done()
	return io.Copy(dest, src)
}

// tryUpgradeConnection attempt to upgrade the connection to a http pdy stream
func tryUpgradeConnection(req *http.Request, writer http.ResponseWriter, endpoint *url.URL) error {
	// step: dial the endpoint
	server, err := tryDialEndpoint(endpoint)
	if err != nil {
		return err
	}
	defer server.Close()

	// @check the the response writer implements the Hijack method
	if _, ok := writer.(http.Hijacker); !ok {
		return errors.New("writer does not implement http.Hijacker method")
	}

	// @step: get the client connection object
	client, _, err := writer.(http.Hijacker).Hijack()
	if err != nil {
		return err
	}
	defer client.Close()

	// step: write the request to upstream
	if err = req.Write(server); err != nil {
		return err
	}

	// @step: copy the data between client and upstream endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { _, _ = transferBytes(server, client, &wg) }()
	go func() { _, _ = transferBytes(client, server, &wg) }()
	wg.Wait()

	return nil
}

// dialAddress extracts the dial address from the url
func dialAddress(location *url.URL) string {
	items := strings.Split(location.Host, ":")
	if len(items) != 2 {
		switch location.Scheme {
		case unsecureScheme:
			return location.Host + ":80"
		default:
			return location.Host + ":443"
		}
	}

	return location.Host
}

// tryDialEndpoint dials the upstream endpoint via plain HTTP
func tryDialEndpoint(location *url.URL) (net.Conn, error) {
	switch dialAddress := dialAddress(location); location.Scheme {
	case unsecureScheme:
		return net.Dial("tcp", dialAddress)
	default:
		return tls.Dial("tcp", dialAddress, &tls.Config{
			Rand: cryptorand.Reader,
			//nolint:gas
			InsecureSkipVerify: true,
		})
	}
}
*/
