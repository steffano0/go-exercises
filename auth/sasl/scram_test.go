package sasl

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type ScramSuite struct{}

var _ = Suite(&ScramSuite{})

func newFixedRandom() io.Reader {
	nonce := []byte("abcabcabcabcabcabcabcabcabcabc")
	return bytes.NewBuffer(append(
		nonce,
		0x01, 0x02, 0x04, 0x08, 0x0F, 0x11, 0x13, 0x18,
		0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
		0x31, 0x02, 0x34, 0x08, 0x2F, 0x11, 0x13, 0x18,
		0x41, 0x02, 0x44, 0x08, 0x3F, 0x11, 0x53, 0x18,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
		0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
		0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
		0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
		0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
		0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
	))
}

func newFixedRandomTestCase1() io.Reader {
	nonce := []byte("%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")

	return bytes.NewBuffer(
		append(nonce,
			0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e,
			0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa, 0x81,
		),
	)
}

// This test is for SHA-256 SCRAM - we will specify this better later

func (s *ScramSuite) Test_scram_step1_returnsAnIterationCountAndSalt(c *C) {
	sc := newScram(newFixedRandom(), nil)

	nonce, salt, it := sc.step1("fooUser", "foo")

	c.Assert(it, Equals, 4096)
	c.Assert(nonce, Equals, "fooabcabcabcabcabcabcabcabcabcabc")
	c.Assert(salt, DeepEquals, []byte{
		0x01, 0x02, 0x04, 0x08, 0x0F, 0x11, 0x13, 0x18,
		0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
	})
}

func (s *ScramSuite) Test_scram_step1_doesntReturnTheSameSaltIfCalledTwice(c *C) {
	sc := newScram(newFixedRandom(), nil)

	_, salt1, _ := sc.step1("fooUser", "")
	_, salt2, _ := sc.step1("fooUser", "")

	c.Assert(salt1, Not(DeepEquals), salt2)
}

func (s *ScramSuite) Test_scram_step1_testFromSha256Spec(c *C) {
	sc := newScram(newFixedRandomTestCase1(), nil)

	nonce, salt, it := sc.step1("user", "rOprNGfwEbeRWgbNEkqO")

	c.Assert(it, Equals, 4096)
	c.Assert(nonce, Equals, "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0")
	c.Assert(salt, DeepEquals, []byte{
		0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa, 0x81,
	})
}

func (s *ScramSuite) Test_scram_step2_testFromSha256Spec(c *C) {
	sc := newScram(newFixedRandomTestCase1(), &hashData{
		h: map[string]string{
			"password":                           "pencil",
			"client-first-message-bare":          "n=user,r=rOprNGfwEbeRWgbNEkqO",
			"server-first-message":               "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
			"client-final-message-without-proof": "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
		},
	})

	_, _, _ = sc.step1("user", "rOprNGfwEbeRWgbNEkqO")

	clientProof, _ := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")

	serverSignature, ok := sc.step2(clientProof)

	expected, _ := base64.StdEncoding.DecodeString("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")

	c.Assert(ok, Equals, true)
	c.Assert(expected, DeepEquals, serverSignature)
}

func (s *ScramSuite) Test_scram_step2_testFromSha256Spec_failsOnWrongPassword(c *C) {
	sc := newScram(newFixedRandomTestCase1(), &hashData{
		h: map[string]string{
			"password":                           "typewriter",
			"client-first-message-bare":          "n=user,r=rOprNGfwEbeRWgbNEkqO",
			"server-first-message":               "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
			"client-final-message-without-proof": "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0",
		},
	})

	_, _, _ = sc.step1("user", "rOprNGfwEbeRWgbNEkqO")

	clientProof, _ := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	serverSignature, ok := sc.step2(clientProof)

	c.Assert(ok, Equals, false)
	c.Assert(serverSignature, IsNil)
}
