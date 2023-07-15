package sasl

import (
	"errors"
	"strings"
)

type channelBindingType string

const clientDoesntSupportChannelBinding channelBindingType = "client doesn't support channel binding"

type firstMessage struct {
	channelBinding channelBindingType
	username       string
	authAs         *string
	nonce          string
}

func parseClientFirstMessage(msg string) (*firstMessage, error) {
	fm := &firstMessage{}

	pieces := strings.Split(msg, ",")

	if len(pieces[2]) <= 2 {
		return nil, errors.New("no value given for username")

	} else if strings.Contains(pieces[2][2:], "=") {
		if !strings.Contains(pieces[2][2:], "=2C") && !strings.Contains(pieces[2][2:], "=3D") {
			return nil, errors.New("invalid character '=' in username")
		}
	} else if pieces[2][:1] != "n" {
		return nil, errors.New("incorrect tag 'q' for username")
	}

	fm.channelBinding = parseChannelBinding(pieces[0])
	fm.authAs = parseAuthAs(pieces[1])
	fm.username = parseUsername(pieces[2])
	fm.nonce = parseNonce(pieces[3])

	return fm, nil
}

func parseChannelBinding(msg string) channelBindingType {
	return clientDoesntSupportChannelBinding
}

func parseAuthAs(msg string) *string {
	return nil
}

func parseUsername(msg string) string {
	username := strings.ReplaceAll(
		strings.ReplaceAll(msg[2:], "=2C", ","),
		"=3D", "=")

	return username
}

func parseNonce(msg string) string {
	return msg[2:]
}
