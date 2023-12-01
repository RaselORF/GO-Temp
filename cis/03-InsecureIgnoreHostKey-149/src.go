// Issue 149
// ssh.InsecureIgnoreHostKey() is assigned as value of HostKeyCallback
// CIS should generate a warning.

package testdata

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

func insecureIgnoreHostKey() {
	_, b := &ssh.ClientConfig{
		User:            "username",
		Auth:            []ssh.AuthMethod{nil},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, "dkfjdk"
	fmt.Print(b)
}

//<<<<<224, 365>>>>>
