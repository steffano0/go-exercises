package sasl

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type serverFirstMessage struct {
	nonce          string
	salt           []byte
	iterationCount uint
}

type ServerFinalMessage interface {
	Unparse() string
}

type ServerError string

const (
	InvalidEncoding                 = ServerError("invalid-encoding")
	ExtensionsNotSupported          = ServerError("extensions-not-supported")
	InvalidProof                    = ServerError("invalid-proof")
	ChannelBindingsDontMatch        = ServerError("channel-bindings-dont-match")
	ServerDoesSupportChannelBinding = ServerError("server-does-support-channel-binding")
	ChannelBindingNotSupported      = ServerError("channel-binding-not-supported")
	UnsupportedChannelBindingType   = ServerError("unsupported-channel-binding-type")
	UnknownUser                     = ServerError("unknown-user")
	InvalidUsernameEncoding         = ServerError("invalid-username-encoding")
	NoResources                     = ServerError("no-resources")
	OtherError                      = ServerError("other-error")
)

type serverFinalMessageVerifier struct {
	verifier []byte
}

func attr(tag, value string) string {
	return fmt.Sprintf("%s=%s", tag, value)
}

func attrBase64(tag string, value []byte) string {
	return attr(tag, base64.StdEncoding.EncodeToString(value))
}

func attrs(values ...string) string {
	return strings.Join(values, ",")
}

func (e ServerError) Unparse() string {
	return attr("e", string(e))
}

func (m *serverFirstMessage) unparse() string {
	return attrs(
		attr("r", m.nonce),
		attrBase64("s", m.salt),
		attr("i", strconv.Itoa(int(m.iterationCount))),
	)
}

func (m *serverFinalMessageVerifier) Unparse() string {
	return attrBase64("v", m.verifier)
}
