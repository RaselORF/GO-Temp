// Issue 23
// Setting InsecureSkipVerify to false in tls.Config is okay.
// No warning will be generated.

package main

import (
	"crypto/tls"
	"net/http"
)

func DoAuthReq(authReq *http.Request) *http.Response {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	client := &http.Client{Transport: tr}
	res, _ := client.Do(authReq)
	return res
}

//<<<<<259, 296>>>>>
