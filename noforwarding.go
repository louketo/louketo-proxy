//+build noforwarding

package main

import (
	"errors"
	"net/http"
)

func (r *Config) isForwardingValid() error {
	return errors.New("forwarding mode is not enabled in this build: you can't enable EnableForwarding")
}

func (r *oauthProxy) createForwardingProxy() error {
	return nil
}

func (r *oauthProxy) forwardProxyHandler() func(*http.Request, *http.Response) {
	return func(_ *http.Request, _ *http.Response) {}
}
