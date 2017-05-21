package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

var stderr *os.File

func setupTTY() {
	var err error
	stderr, err = os.OpenFile(os.Getenv("GPG_TTY"), os.O_RDWR, 0)
	if err != nil {
		stderr, err = os.OpenFile(os.Getenv("TTY"), os.O_RDWR, 0)
		if err != nil {
			stderr = os.Stderr
		}
	}
}

func main() {
	exec.Command("export", "GPG_TTY=`tty`").Run()
	setupTTY()
	stderr.WriteString(fmt.Sprintf("%v\r\n", os.Args))
	stdin, _ := ioutil.ReadAll(os.Stdin)
	stderr.WriteString(string(stdin) + "\r\n")
	stdinreader := bytes.NewReader(stdin)
	cmd := exec.Command("gpg", "--status-fd=2", "-bsau", "C2E6E330")
	stdoutbuf := &bytes.Buffer{}
	cmd.Stdin = stdinreader
	cmd.Stdout = stdoutbuf
	cmd.Stderr = os.Stderr
	cmd.Run()
	os.Stderr.Write(stdoutbuf.Bytes())
	os.Stdout.Write(stdoutbuf.Bytes())
}
