// Issue 149
// ssh.InsecureIgnoreHostKey() is assigned as value of HostKeyCallback
// CIS should generate a warning.

package testdata

import (
	"golang.org/x/crypto/ssh"
)

func insecureIgnoreHostKey() {
	_ = &ssh.ClientConfig{
		User:            "username",
		Auth:            []ssh.AuthMethod{nil},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

//<<<<<213, 354>>>>>
