package sasl

import (
	"encoding/base64"

	. "gopkg.in/check.v1"
)

type ParserSuite struct{}

var _ = Suite(&ParserSuite{})

func (s *ParserSuite) Test_parseClientFirstMessage_returnsACorrectlyParsedMessage(c *C) {
	msg := "n,,n=so=2Cmeo=3Dne,r=blablabla"

	result, e := parseClientFirstMessage(msg)

	c.Assert(e, IsNil)

	c.Assert(result.channelBinding, Equals, clientDoesntSupportChannelBinding)
	c.Assert(result.authAs, IsNil)
	c.Assert(result.username, Equals, "so,meo=ne")
	c.Assert(result.nonce, Equals, "blablabla")
}

func (s *ParserSuite) Test_parseClientFirstMessage_parsesChannelBindingsCorrectly(c *C) {
	msg := "n,,n=foo,r=blablabla"
	result, e := parseClientFirstMessage(msg)
	c.Assert(e, IsNil)
	c.Assert(result.channelBinding, Equals, clientDoesntSupportChannelBinding)

	msg = "y,,n=foo,r=blablabla"
	result, e = parseClientFirstMessage(msg)
	c.Assert(e, IsNil)
	c.Assert(result.channelBinding, Equals, clientSupportsChannelBinding)

	msg = "p=tls-unique,,n=foo,r=blablabla"
	result, e = parseClientFirstMessage(msg)
	c.Assert(e, IsNil)
	c.Assert(result.channelBinding, Equals, clientRequiresChannelBinding)
	c.Assert(result.channelBindingType, Equals, "tls-unique")

	msg = "p=ssl-super-safe,,n=foo,r=blablabla"
	result, e = parseClientFirstMessage(msg)
	c.Assert(e, IsNil)
	c.Assert(result.channelBinding, Equals, clientRequiresChannelBinding)
	c.Assert(result.channelBindingType, Equals, "ssl-super-safe")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnErrorWhenWrongTagIsUsedForUsername(c *C) {
	msg := "n,,q=bla,r=blablabla"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for username")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnErrorWhenNoValueIsGivenForRequiredUsername(c *C) {
	msg := "n,,q=,r=blablabla"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for username")

	msg = "n,,,r=blablabla"

	_, e = parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for username")

}

func (s *ParserSuite) Test_parseClientFirstMessage_storesValidAuthAs(c *C) {
	msg := "n,a=some,n=bla,r=blablabla"

	r, e := parseClientFirstMessage(msg)

	c.Assert(e, IsNil)
	c.Assert(*r.authAs, Equals, "some")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesErrorForIncorrectAuthAs(c *C) {
	msg := "n,abcbla,n=bla,r=blablabla"

	r, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for authas")
	c.Assert(r, IsNil)

	msg = "n,s=sab,n=bla,r=blablabla"

	r, e = parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for authas")
	c.Assert(r, IsNil)
}

func (s *ParserSuite) Test_parseClientFirstMessage_isEmptyWhenGivenNoValue(c *C) {
	msg := "n,a=,n=bla,r=blablabla"

	r, e := parseClientFirstMessage(msg)

	c.Assert(e, IsNil)
	c.Assert(r.authAs, IsNil)

	msg = "n,,n=bla,r=blablabla"

	r, e = parseClientFirstMessage(msg)

	c.Assert(e, IsNil)
	c.Assert(r.authAs, IsNil)
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnErrorWhenInvalidCaracterFoundInUsername(c *C) {

	msg := "n,,n=b=a,r=blablabla"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "invalid character '=' in username")

	msg = "n,,n=b=2C=a,r=blablabla"

	_, e = parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "invalid character '=' in username")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnError_forIncorrectValueForChannelBinding(c *C) {
	msg := "rrr,,n=foo,r=bar"
	_, e := parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "nn,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "q,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "n=bla,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "y=bla,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "p,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "p=,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "pbb,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")

	msg = "pbp=,,n=foo,r=bar"
	_, e = parseClientFirstMessage(msg)
	c.Assert(e, ErrorMatches, "invalid value for channel binding")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnError_whenNoAuthAsIsGiven(c *C) {
	msg := "n"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "no value given for authas")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnError_whenNoUsernameGiven(c *C) {
	msg := "n,"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "no value given for username")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnError_whenNoNonceGiven(c *C) {
	msg := "n,,n=a"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "no value given for nonce")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnError_whenNoNonceValueGiven(c *C) {
	msg := "n,,n=a,r="

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for nonce")

	msg = "n,,n=a,"

	_, e = parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for nonce")
}

func (s *ParserSuite) Test_parseClientFirstMessage_generatesAnError_whenIncorrectNonceTagIsGiven(c *C) {
	msg := "n,,n=a,q=gfdsfg"

	_, e := parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for nonce")

	msg = "n,,n=a,rfr"

	_, e = parseClientFirstMessage(msg)

	c.Assert(e, ErrorMatches, "incorrect tag or value for nonce")
}

// base64Dec decodes the base64 string given, ignoring errors
func base64Dec(s string) []byte {
	result, _ := base64.StdEncoding.DecodeString(s)
	return result
}

func (s *ParserSuite) Test_parseClientSecondMessage_returnsACorrectlyParsedMessage(c *C) {
	msg := "c=biws,r=rOprNGfwEbeRWgbN,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

	result, e := parseClientSecondMessage(msg)

	c.Assert(e, IsNil)
	c.Assert(result.headerAndChannelBindingData, Equals, "biws")
	c.Assert(result.nonce, Equals, "rOprNGfwEbeRWgbN")
	c.Assert(result.clientProof, DeepEquals, base64Dec("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="))
}

func (s *ParserSuite) Test_parseClientSecondMessage_generatesAnError_whenIncorrectChannelBindingDataTagOrValueIsGiven(c *C) {
	msg := "q=biws,r=rOprNGfwEbeRWgbN,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

	result, e := parseClientSecondMessage(msg)

	c.Assert(result, IsNil)
	c.Assert(e, ErrorMatches, "incorrect tag or value for channel binding data")

}

func (s *ParserSuite) Test_parseClientSecondMessage_generatesAnError_whenIncorrectNonceTagOrValueIsGiven(c *C) {
	msg := "c=biws,b=rOprNGfwEbeRWgbN,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

	result, e := parseClientSecondMessage(msg)

	c.Assert(result, IsNil)
	c.Assert(e, ErrorMatches, "incorrect tag or value for nonce")
}

func (s *ParserSuite) Test_parseClientSecondMessage_generatesAnError_whenIncorrectClientProofTagOrValueIsGiven(c *C) {
	msg := "c=biws,r=rOprNGfwEbeRWgbN,s=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

	result, e := parseClientSecondMessage(msg)

	c.Assert(result, IsNil)
	c.Assert(e, ErrorMatches, "incorrect tag or value for client proof")
}
