// Issue 149
// ssh.InsecureIgnoreHostKey() is assigned as value of HostKeyCallback
// CIS should generate a warning.

package testdata

import (
	. "golang.org/x/crypto/ssh"
)

func insecureIgnoreHostKey() {
	_ = &ClientConfig{
		User:            "username",
		Auth:            []AuthMethod{nil},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}
}

//<<<<<215, 344>>>>>
