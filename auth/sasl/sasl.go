package sasl

import (
	"io"

	"github.com/digitalautonomy/goxes/auth"
)

type Authentication interface {
	Response([]byte)
}

type scramAuthentication struct {
	data      *hashData
	scram     *scram
	challenge func([]byte)
	success   func()
	failure   func()
}

func (a *scramAuthentication) start(initialData []byte, userDb auth.Database) {

	msg, _ := parseClientFirstMessage(string(initialData))

	user, _ := userDb.GetUser(msg.username)

	a.data.h["password"] = user.GetPassword()

	a.data.h["client-first-message-bare"] = msg.messageBare

	nonce, salt, iterations := a.scram.step1(msg.username, msg.nonce)

	msg1 := &serverFirstMessage{
		nonce:          nonce,
		salt:           salt,
		iterationCount: uint(iterations),
	}

	msg1ToSend := msg1.unparse()

	a.data.h["server-first-message"] = msg1ToSend

	a.challenge([]byte(msg1ToSend))
}

func NewAuthentication(mechanism string, userDb auth.Database, initialData []byte, success func(), failure func(), challenge func(v []byte), r io.Reader) Authentication {
	data := &hashData{
		h: map[string]string{},
	}

	auth := &scramAuthentication{
		data:      data,
		scram:     newScram(r, data),
		challenge: challenge,
		success:   success,
		failure:   failure,
	}

	auth.start(initialData, userDb)

	return auth
}

func (a *scramAuthentication) Response(data []byte) {
	msg, _ := parseClientSecondMessage(string(data))
	a.data.h["client-final-message-without-proof"] = msg.messageWithoutProof

	_, ok := a.scram.step2(msg.clientProof)

	if !ok {
		a.failure()
		return
	}

	a.success()

	// msg2 = &serverFinalMessageVerifier{
	// 	verifier: serverSignature,
	// }

	// TODO: do stuff
}
