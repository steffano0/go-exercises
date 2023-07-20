package sasl

import (
	"encoding/base64"
	"errors"
	"fmt"
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
	messageBare        string
}

type secondMessage struct {
	headerAndChannelBindingData string
	nonce                       string
	clientProof                 []byte
	messageWithoutProof         string
}

func parseClientFirstMessage(msg string) (*firstMessage, error) {
	fm := &firstMessage{}

	var err error
	pieces := strings.Split(msg, ",")

	fm.channelBinding, fm.channelBindingType, err = parseChannelBinding(pieces[0])
	if err != nil {
		return nil, err
	}

	fm.authAs, err = parseOptionalAttribute(pieces, 1, "authas", "a")
	if err != nil {
		return nil, err
	}

	fm.username, err = parseDecodedAttribute(pieces, 2, "username", "n")
	if err != nil {
		return nil, err
	}

	fm.nonce, err = parseSimpleAttribute(pieces, 3, "nonce", "r")
	if err != nil {
		return nil, err
	}

	fm.messageBare = strings.Join(pieces[2:], ",")

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

func parseOptionalAttribute(pieces []string, index int, name string, tag string) (*string, error) {
	if len(pieces) < index+1 {
		return nil, fmt.Errorf("no value given for %s", name)
	}

	msg := pieces[index]

	if len(msg) == 0 {
		return nil, nil
	}

	prefix := fmt.Sprintf("%s=", tag)

	if strings.HasPrefix(msg, prefix) {
		val := strings.TrimPrefix(msg, prefix)
		if val == "" {
			return nil, nil

		}
		return &val, nil
	}

	return nil, fmt.Errorf("incorrect tag or value for %s", name)
}

func hasFloatingEqualSigns(msg string) bool {
	strWithoutReplacements := strings.ReplaceAll(
		strings.ReplaceAll(msg, "=2C", ""), "=3D", "")
	return strings.Contains(strWithoutReplacements, "=")
}

func decode(msg string) (string, bool) {
	if hasFloatingEqualSigns(msg) {
		return "", false
	}

	return strings.ReplaceAll(
		strings.ReplaceAll(msg, "=2C", ","),
		"=3D", "="), true
}

func parseBase64Attribute(pieces []string, index int, name string, tag string) ([]byte, error) {
	res, err := parseSimpleAttribute(pieces, index, name, tag)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(res)
}

type decodeError struct {
	name      string
	character rune
}

func (e *decodeError) Error() string {
	return fmt.Sprintf("invalid character '%c' in %s", e.character, e.name)
}

func parseDecodedAttribute(pieces []string, index int, name string, tag string) (string, error) {
	res, err := parseSimpleAttribute(pieces, index, name, tag)
	if err != nil {
		return "", err
	}

	res2, ok := decode(res)
	if !ok {
		return "", &decodeError{character: '=', name: name}
	}

	return res2, nil
}

func parseSimpleAttribute(pieces []string, index int, name string, tag string) (string, error) {
	if len(pieces) < index+1 {
		return "", fmt.Errorf("no value given for %s", name)
	}

	msg := pieces[index]

	prefix := fmt.Sprintf("%s=", tag)

	incorrectError := fmt.Errorf("incorrect tag or value for %s", name)

	if strings.HasPrefix(msg, prefix) {
		val := strings.TrimPrefix(msg, prefix)
		if val == "" {
			return "", incorrectError
		}
		return val, nil
	}
	return "", incorrectError

}

func parseClientSecondMessage(msg string) (*secondMessage, error) {
	sm := &secondMessage{}

	var err error
	pieces := strings.Split(msg, ",")

	sm.headerAndChannelBindingData, err = parseSimpleAttribute(pieces, 0, "channel binding data", "c")
	if err != nil {
		return nil, err
	}

	sm.nonce, err = parseSimpleAttribute(pieces, 1, "nonce", "r")
	if err != nil {
		return nil, err
	}

	sm.clientProof, err = parseBase64Attribute(pieces, 2, "client proof", "p")
	if err != nil {
		return nil, err
	}

	sm.messageWithoutProof = strings.Join(pieces[:2], ",")

	return sm, nil

}
