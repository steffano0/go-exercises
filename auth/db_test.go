package auth

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type AuthSuite struct{}

var _ = Suite(&AuthSuite{})

func newUser(usern string, passw string) User {
	user := &user{
		username: usern,
		password: passw,
	}
	return user
}

func (s *AuthSuite) Test_getUser(c *C) {
	database := NewDatabase()

	user := newUser("username", "1234")

	err := database.AddUser(user)
	c.Assert(err, IsNil)

	retrievedUser, err := database.GetUser("username")

	c.Assert(err, IsNil)

	c.Assert(retrievedUser, DeepEquals, user)

	retrievedUser, err = database.GetUser("non-user")
	c.Assert(err, ErrorMatches, "user non existent")
	c.Assert(retrievedUser, IsNil)
}
