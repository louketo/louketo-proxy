package main

import "net/http"

// storage is used to hold the offline refresh token, assuming you don't want to use
// the default practice of a encrypted cookie
type storage interface {
	// Set the token to the store
	Set(string, string) error
	// Get retrieves a token from the store
	Get(string) (string, error)
	// Delete removes a key from the store
	Delete(string) error
	// Close is used to close off any resources
	Close() error
}

// reverseProxy is a wrapper for any underlying handler
type reverseProxy interface {
	ServeHTTP(rw http.ResponseWriter, req *http.Request)
}
