/*
Command cryptstream encrypts/decrypts from stdin to stdout using AES-CBC.

The configuration, including the key, is read from cryptstream.conf.
For now, only AES-CBC (with 128, 192 and 256-bit keys) is supported.

To encrypt:

	echo hi | cryptstream encrypt >hi.encrypted

To decrypt:

	cryptstream decrypt < hi.encrypted

For this to work, a file "cryptstream.conf" has to exist in the
current working directory, or a directory higher up.  It must contain
an AES key in hexadecimal format, like so:

	hex cb6516454a01e28a381d5059ff7cf8774134708516342e839535be6ef2a9fd54

A key can be generated with cryptstream:

	cryptstream key

By default, "key" generates 256-bit keys. Add a parameter "128" or
"192" for other key sizes.

This command was created for streaming backups to cloud storage providers, e.g.:

	tar -cf - somedir | gzip | cryptstream encrypt | cloudstream put /mybucket/mybackup-1.tgz.enc
*/
package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"fmt"
	"io"
	"path"

	"bitbucket.org/mjl/cryptstream/crypt"

        "bitbucket.org/mjl/tokenize"
)

func usage() {
	fail("usage: cryptstream [encrypt | decrypt | key [128 | 192 | 256]]")
}

func fail(s string) {
	fmt.Fprintln(os.Stderr, s)
	os.Exit(1)
}

// looks for config file in current directory, then directories higher up
func findconfig(p, name string) string {
	var err error
	if p != "" {
		p, err = os.Getwd()
		if err != nil {
			fail(fmt.Sprintf("finding %s: %s", name, err))
		}
	}
	for {
		pp := p + "/" + name
		if _, err = os.Stat(pp); !os.IsNotExist(err) {
			return pp
		}
		np := path.Dir(p)
		if np == p {
			break
		}
		p = np
	}
	fail("could not find " + name)
	panic("")
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	var key []byte

	parseconfig := func() {
		lines, err := tokenize.File(findconfig("", "cryptstream.conf"))
		if err != nil {
			fail(err.Error())
		}
		for _, t := range lines {
			cmd, t := t[0], t[1:]
			need := func(n int) {
				if len(t) != n {
					fail(fmt.Sprintf("bad parameters for %q, expected %d, saw %d", cmd, n, len(t)))
				}
			}
			switch cmd {
			case "key":
				need(1)
				key, err = hex.DecodeString(t[0])
				if err != nil {
					fail("bad key, invalid hex")
				}
			default:
				fail(fmt.Sprintf("bad config line %q", cmd))
			}
		}
	}

	cmd, args := os.Args[1], os.Args[2:]
	need := func(n int) {
		if n != len(args) {
			fail(fmt.Sprintf("bad parameters for %q, expected %d, saw %d", cmd, n, len(args)))
		}
	}
	switch cmd {
	default:
		usage()

	case "encrypt":
		need(0)
		parseconfig()
		_, err := io.Copy(os.Stdout, cryptstream.Encrypter(key, nil, os.Stdin))
		if err != nil {
			fail(err.Error())
		}

	case "decrypt":
		need(0)
		parseconfig()
		_, err := io.Copy(os.Stdout, cryptstream.Decrypter(key, os.Stdin))
		if err != nil {
			fail(err.Error())
		}

	case "key":
		var n int
		switch len(args) {
		default:
			usage()
		case 0:
			n = 32
		case 1:
			switch args[0] {
			case "128":
				n = 16
			case "192":
				n = 24
			case "256":
				n = 32
			default:
				fail(fmt.Sprintf("bad size %q", args[0]))
			}
		}
		buf := make([]byte, n)
		_, err := rand.Read(buf)
		if err != nil {
			fail(err.Error())
		}
		fmt.Printf("%x\n", buf)
	}
}
