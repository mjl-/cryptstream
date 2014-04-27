package main

import (
	"testing"
	"encoding/hex"
	"bytes"
	"crypto/rand"
	"io"

	"bitbucket.org/mjl/cryptstream/crypt"
)

var key128, key192, key256 []byte

func init() {
	key128, _ = hex.DecodeString("e835dc07aeb177466ad54d1e91f4a648")
	key192, _ = hex.DecodeString("71c7fc037ad1e746131f0aeeff69a4bcd04369c688d11a25")
	key256, _ = hex.DecodeString("6d992c54605715b77207a2e650b17e32b4b153705b969ecaef7bd8bb6d1709f0")
}

func TestBoth(t *testing.T) {
	const blocksize = 16
	lengths := []int{0, 1, 15, 16, 17, 64*1024-blocksize-1, 64*1024-blocksize, 64*1024-blocksize+1, 64*2014-blocksize+7}
	for _, key := range [][]byte{key128, key192, key256} {
		for _, n := range lengths {
			buf := make([]byte, n)
			_, err := rand.Read(buf)
			if err != nil {
				t.Fatal("bad random", err)
			}
			b := new(bytes.Buffer)
			_, err = io.Copy(b, cryptstream.Decrypter(key, cryptstream.Encrypter(key, nil, bytes.NewBuffer(buf))))
			if err != nil {
				t.Fatal("bad encryption/decryption", err)
			}
			if !bytes.Equal(b.Bytes(), buf) {
				t.Fatal("decrypter after encryption did not recover original")
			}
		}
	}
}
