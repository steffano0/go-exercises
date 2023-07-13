package sasl

import (
	"crypto/rand"
	"io"
	"unicode"
)

func randomReader(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

type scram struct {
	r io.Reader
}

func newScram(r io.Reader) *scram {
	return &scram{
		r: randomReader(r),
	}
}

const saltSize = 16
const nonceSize = 30
const iterations = 4096

func generatePrintableCharacter(r io.Reader) rune {
	buf := make([]byte, 1)
	for {
		_, _ = io.ReadFull(r, buf)
		c := rune(buf[0])
		if unicode.IsPrint(c) && c != ',' {
			return c
		}
	}
}

func (s *scram) generateSalt() []byte {
	buf := make([]byte, saltSize)
	// We assume that cryptographic randomness can't generate errors
	// We also assume that ReadFull will read the exact amount necessary
	_, _ = io.ReadFull(s.r, buf)
	return buf
}

func (s *scram) generateServerNonce() string {
	data := make([]rune, nonceSize)
	for ix := range data {
		data[ix] = generatePrintableCharacter(s.r)
	}
	return string(data)
}

func (s *scram) step1(user, cnonce string) (string, []byte, int) {
	snonce := s.generateServerNonce()
	salt := s.generateSalt()
	return cnonce + snonce, salt, iterations
}

func (s *scram) step2()
