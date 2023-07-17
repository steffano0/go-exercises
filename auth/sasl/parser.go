package sasl

import (
	"errors"
	"strings"
)

type channelBindingType string

const clientDoesntSupportChannelBinding channelBindingType = "client doesn't support channel binding"
const clientSupportsChannelBinding channelBindingType = "client supports channel binding"
const clientRequiresChannelBinding channelBindingType = "client requires channel binding"

type firstMessage struct {
	channelBinding     channelBindingType
	channelBindingType string
	username           string
	authAs             *string
	nonce              string
}

type secondMessage struct {
	nonce              string
	channelBindingType string
	clientProof        string
	authAs             *string
}

func parseClientFirstMessage(msg string) (*firstMessage, error) {
	fm := &firstMessage{}

	var err error
	pieces := strings.Split(msg, ",")

	fm.channelBinding, fm.channelBindingType, err = parseChannelBinding(pieces[0])
	if err != nil {
		return nil, err
	}

	if len(pieces) < 2 {
		return nil, errors.New("no value given for authas")
	}
	fm.authAs, err = parseAuthAs(pieces[1])
	if err != nil {
		return nil, err
	}

	if len(pieces) < 3 {
		return nil, errors.New("no value given for username")
	}
	fm.username, err = parseUsername(pieces[2])
	if err != nil {
		return nil, err
	}

	if len(pieces) < 4 {
		return nil, errors.New("no value given for nonce")
	}
	fm.nonce, err = parseNonce(pieces[3])
	if err != nil {
		return nil, err
	}

	return fm, nil
}

func parseChannelBinding(msg string) (channelBindingType, string, error) {
	if strings.HasPrefix(msg, "p=") {
		val := strings.TrimPrefix(msg, "p=")
		if val != "" {
			return clientRequiresChannelBinding, val, nil
		}
	} else {
		switch msg {
		case "y":
			return clientSupportsChannelBinding, "", nil
		case "n":
			return clientDoesntSupportChannelBinding, "", nil
		}
	}
	return "", "", errors.New("invalid value for channel binding")
}

func parseAuthAs(msg string) (*string, error) {
	if len(msg) == 0 {
		return nil, nil
	}
	if strings.HasPrefix(msg, "a=") {
		val := strings.TrimPrefix(msg, "a=")
		if val == "" {
			return nil, nil

		}
		return &val, nil
	}

	return nil, errors.New("incorrect tag or value for authas")
}

func hasFloatingEqualSigns(msg string) bool {
	strWithoutReplacements := strings.ReplaceAll(
		strings.ReplaceAll(msg, "=2C", ""), "=3D", "")
	return strings.Contains(strWithoutReplacements, "=")
}

func expectTag(msg, name string) (string, bool) {
	pieces := strings.SplitN(msg, "=", 2)

	if len(pieces) < 2 {
		return "", false
	}

	if pieces[0] != name {
		return "", false
	}

	return pieces[1], true
}

func urlDecode(msg string) (string, bool) {
	if hasFloatingEqualSigns(msg) {
		return "", false
	}

	return strings.ReplaceAll(
		strings.ReplaceAll(msg, "=2C", ","),
		"=3D", "="), true
}

func parseUsername(msg string) (string, error) {
	rest, hasCorrectTag := expectTag(msg, "n")
	if !hasCorrectTag {
		return "", errors.New("incorrect tag or value for username")
	}

	username, correctEncoding := urlDecode(rest)
	if !correctEncoding {
		return "", errors.New("invalid character '=' in username")
	}

	return username, nil
}

func parseNonce(msg string) (string, error) {
	if strings.HasPrefix(msg, "r=") {
		val := strings.TrimPrefix(msg, "r=")
		if val == "" {
			return "", errors.New("incorrect tag or value for nonce")
		}
		return val, nil
	}
	return "", errors.New("incorrect tag or value for nonce")
}

func parseClientSecondMessage(msg string) (*secondMessage, error) {
	sm := &secondMessage{}
	return sm, nil

}
