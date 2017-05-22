package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/kryptco/kr"
	"github.com/kryptco/kr/krdclient"
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

func readLineIgnoringFirstToken(reader *bufio.Reader) (b []byte, err error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	toks := strings.Fields(line)
	if len(toks) == 0 {
		err = fmt.Errorf("no tokens")
		return
	}
	b = []byte(strings.Join(toks[1:], " "))
	return
}

func main() {
	setupTTY()
	stdinBytes, _ := ioutil.ReadAll(os.Stdin)
	stderr.WriteString(string(stdinBytes))
	reader := bufio.NewReader(bytes.NewReader(stdinBytes))
	tree, err := readLineIgnoringFirstToken(reader)
	if err != nil {
		stderr.WriteString("error parsing commit tree")
		stderr.WriteString(err.Error())
		os.Exit(1)
	}
	parent, err := readLineIgnoringFirstToken(reader)
	if err != nil {
		stderr.WriteString("error parsing commit parent")
		stderr.WriteString(err.Error())
		os.Exit(1)
	}
	author, err := readLineIgnoringFirstToken(reader)
	if err != nil {
		stderr.WriteString("error parsing commit author")
		stderr.WriteString(err.Error())
		os.Exit(1)
	}
	committer, err := readLineIgnoringFirstToken(reader)
	if err != nil {
		stderr.WriteString("error parsing commit committer")
		stderr.WriteString(err.Error())
		os.Exit(1)
	}
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		stderr.WriteString("error parsing commit message")
		stderr.WriteString(err.Error())
		os.Exit(1)
	}
	commit := kr.CommitInfo{
		Tree:      tree,
		Parent:    parent,
		Author:    author,
		Committer: committer,
		Message:   message,
	}
	fp, err := hex.DecodeString(os.Args[len(os.Args)-1])
	if err != nil {
		fp = []byte{}
	}
	request := kr.GitSignRequest{
		Commit:               commit,
		PublicKeyFingerprint: fp,
	}
	response, err := krdclient.RequestGitSignature(request)
	if err != nil {
		stderr.WriteString(err.Error())
		os.Exit(1)
	}
	sig, err := response.AsciiArmorSignature()
	if err != nil {
		stderr.WriteString(err.Error())
		os.Exit(1)
	}
	os.Stdout.WriteString(sig)
	os.Stdout.Write([]byte("\n"))
	os.Stdout.Close()
	os.Stderr.WriteString("\n[GNUPG:] SIG_CREATED ")
	os.Exit(0)
}
