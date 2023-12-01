// Issue 23
// Setting InsecureSkipVerify to false in tls.Config is okay.
// No warning will be generated.

package main

import (
	"crypto/tls"
	"net/http"
)

func DoAuthReq(authReq *http.Request) *http.Response {
	conf := tls.Config{}
	conf.InsecureSkipVerify = false
	tr := &http.Transport{
		TLSClientConfig: &conf,
	}
	client := &http.Client{Transport: tr}
	res, _ := client.Do(authReq)
	return res
}

//<<<<<238, 269>>>>>
