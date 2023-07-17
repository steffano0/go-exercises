package sasl

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"strings"
	"unicode"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/transform"
)

func randomReader(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// This implements SCRAM-SHA256 and SCRAM-SHA256-PLUS

// This type can be used with or without channel binding - it doesn't change the calculations
// The channel binding information is optionally included in the authMessage() production
// The verification of channel binding should happen at a higher level

type scram struct {
	r          io.Reader
	hf         func() hash.Hash
	data       data
	salt       []byte
	iterations int
}

type data interface {
	get(string) string
}

type hashData struct {
	h map[string]string
}

func (h *hashData) get(key string) string {
	return h.h[key]
}

func newScram(r io.Reader, d data) *scram {
	return &scram{
		r:    randomReader(r),
		hf:   sha256.New,
		data: d,
	}
}

const saltSize = 16
const nonceSize = 30
const defaultIterations = 4096

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
	s.salt = s.generateSalt()
	s.iterations = defaultIterations
	return cnonce + snonce, s.salt, s.iterations
}

func (s *scram) normalize(input string) ([]byte, error) {
	r := transform.NewReader(strings.NewReader(input), stringprep)
	return io.ReadAll(r)
}

func (s *scram) h(data []byte) []byte {
	h := s.hf()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func (s *scram) hmac(key []byte, data []byte) []byte {
	h := hmac.New(s.hf, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// xorBytes will xor two arrays of equal length together
func xorBytes(left, right []byte) []byte {
	result := make([]byte, len(left))

	for ix, l := range left {
		result[ix] = l ^ right[ix]
	}

	return result
}

func (s *scram) hi(str []byte, salt []byte, i int) []byte {
	return pbkdf2.Key(str, salt, i, s.hf().Size(), s.hf)
}

func (s *scram) password() string {
	return s.data.get("password")
}

func (s *scram) authMessage() string {
	return fmt.Sprintf("%s,%s,%s",
		s.data.get("client-first-message-bare"),
		s.data.get("server-first-message"),
		s.data.get("client-final-message-without-proof"),
	)
}

func (s *scram) saltedPassword() []byte {
	normalizedPassword, _ := s.normalize(s.password())
	return s.hi(normalizedPassword, s.salt, s.iterations)
}

func (s *scram) clientKey() []byte {
	return s.hmac(s.saltedPassword(), []byte("Client Key"))
}

func (s *scram) serverKey() []byte {
	return s.hmac(s.saltedPassword(), []byte("Server Key"))
}

func (s *scram) clientSignature() []byte {
	storedKey := s.h(s.clientKey())
	return s.hmac(storedKey, []byte(s.authMessage()))
}

func (s *scram) serverSignature() []byte {
	return s.hmac(s.serverKey(), []byte(s.authMessage()))
}

func (s *scram) validClientProof(proof []byte) bool {
	theirClientKey := xorBytes(proof, s.clientSignature())
	result := subtle.ConstantTimeCompare(theirClientKey, s.clientKey())
	return result == 1
}

func (s *scram) step2(clientProof []byte) ([]byte, bool) {
	if !s.validClientProof(clientProof) {
		return nil, false
	}

	return s.serverSignature(), true
}
