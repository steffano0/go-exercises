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

type serverFinalMessage interface {
	unparse() string
}

type serverError string

const (
	invalidEncoding                 = serverError("invalid-encoding")
	extensionsNotSupported          = serverError("extensions-not-supported")
	invalidProof                    = serverError("invalid-proof")
	channelBindingsDontMatch        = serverError("channel-bindings-dont-match")
	serverDoesSupportChannelBinding = serverError("server-does-support-channel-binding")
	channelBindingNotSupported      = serverError("channel-binding-not-supported")
	unsupportedChannelBindingType   = serverError("unsupported-channel-binding-type")
	unknownUser                     = serverError("unknown-user")
	invalidUsernameEncoding         = serverError("invalid-username-encoding")
	noResources                     = serverError("no-resources")
	otherError                      = serverError("other-error")
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

func (e serverError) unparse() string {
	return attr("e", string(e))
}

func (m *serverFirstMessage) unparse() string {
	return attrs(
		attr("r", m.nonce),
		attrBase64("s", m.salt),
		attr("i", strconv.Itoa(int(m.iterationCount))),
	)
}

func (m *serverFinalMessageVerifier) unparse() string {
	return attrBase64("v", m.verifier)
}
