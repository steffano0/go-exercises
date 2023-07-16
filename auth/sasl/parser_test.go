package sasl

import (
	"testing"

	. "gopkg.in/check.v1"
)

type ParserSuite struct{}

var _ = Suite(&ParserSuite{})

func Test(t *testing.T) { TestingT(t) }

func (s *ParserSuite) Test_parseClientFirstMessage_returnsACorrectlyParsedMessage(c *C) {
	msg := "n,,n=so=2Cmeo=3Dne,r=blablabla"

	result, e := parseClientFirstMessage(msg)

	c.Assert(e, IsNil)

	c.Assert(result.channelBinding, Equals, clientDoesntSupportChannelBinding)
	c.Assert(result.authAs, IsNil)
	c.Assert(result.username, Equals, "so,meo=ne")
	c.Assert(result.nonce, Equals, "blablabla")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnErrorWhenWrongTagIsUsedForUsername(c *C) {
	msg := "n,,q=bla,r=blablabla"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag 'q' for username")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnErrorWhenNoValueIsGivenForRequiredUsername(c *C) {
	msg := "n,,q=,r=blablabla"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "no value given for username")

	msg = "n,,,r=blablabla"

	_, e = parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "no value given for username")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnErrorWhenInvalidCaracterFoundInUsername(c *C) {
	msg := "n,,q=b=a=2C,r=blablabla"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "invalid character '=' in username")
}
