package sasl

import (
	"github.com/digitalautonomy/goxes/auth"
	. "gopkg.in/check.v1"
)

type SaslSuite struct{}

var _ = Suite(&SaslSuite{})

func (s *SaslSuite) Test_NewAuthentication_worksWithBasicExample(c *C) {
	userdb := auth.NewDatabase()
	userdb.AddUser(auth.NewUser("user", "pencil"))

	successCalled := false

	success := func() {
		successCalled = true
	}

	failureCalled := false
	failure := func() {
		failureCalled = true
	}

	var challengeCalledWith []byte
	challenge := func(v []byte) {
		challengeCalledWith = v
	}

	auth := NewAuthentication("SCRAM-SHA-256", userdb, []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"), success, failure, challenge, newFixedRandomTestCase1())

	c.Assert(challengeCalledWith, DeepEquals, []byte("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"))
	auth.Response([]byte("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="))

	c.Assert(successCalled, Equals, true)
	c.Assert(failureCalled, Equals, false)
}

func (s *SaslSuite) Test_NewAuthentication_failsOnIncorrectPassword(c *C) {
	userdb := auth.NewDatabase()
	userdb.AddUser(auth.NewUser("user", "pen"))

	successCalled := false

	success := func() {
		successCalled = true
	}

	failureCalled := false
	failure := func() {
		failureCalled = true
	}

	challenge := func(v []byte) {
	}

	auth := NewAuthentication("SCRAM-SHA-256", userdb, []byte("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"), success, failure, challenge, newFixedRandomTestCase1())
	auth.Response([]byte("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="))

	c.Assert(successCalled, Equals, false)
	c.Assert(failureCalled, Equals, true)
}
