// Issue 23
// Setting InsecureSkipVerify to true in tls.Config will
// disable certificate verification.
// Warning will be generated.

package main

import (
	"crypto/tls"
	"net/http"
)

func DoAuthReq(authReq *http.Request) *http.Response {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, _ := client.Do(authReq)
	return res
}

//<<<<<288, 324>>>>>
