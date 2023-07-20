package sasl

import (
	. "gopkg.in/check.v1"
)

type UnparserSuite struct{}

var _ = Suite(&UnparserSuite{})

func (s *UnparserSuite) Test_serverFirstMessage_unparse_returnsCorrectlyUnparsedMessage(c *C) {
	msg := &serverFirstMessage{
		nonce: "bla",
		salt: []byte{
			0x01, 0x02, 0x04, 0x08, 0x0F, 0x11, 0x13, 0x18,
			0x21, 0x02, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
		},
		iterationCount: 4096,
	}

	result := msg.unparse()

	c.Assert(result, Equals, "r=bla,s=AQIECA8RExghAiQIPxEjGA==,i=4096")
}

func (s *UnparserSuite) Test_serverError_unparse_returnsCorrectlyUnparsedMessage(c *C) {
	c.Assert(ChannelBindingNotSupported.Unparse(), Equals, "e=channel-binding-not-supported")
	c.Assert(InvalidEncoding.Unparse(), Equals, "e=invalid-encoding")
}

func (s *UnparserSuite) Test_serverFinalMessageVerifier_unparse_returnsCorrectlyUnparsedMessage(c *C) {
	msg := &serverFinalMessageVerifier{
		verifier: []byte{
			0x01, 0xFF, 0x04, 0x08, 0x0F, 0x11, 0x13, 0x18,
			0x21, 0x32, 0x24, 0x08, 0x3F, 0x11, 0x23, 0x18,
		},
	}

	result := msg.Unparse()

	c.Assert(result, Equals, "v=Af8ECA8RExghMiQIPxEjGA==")
}
