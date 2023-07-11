package goxes

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type AuthSuite struct{}

var _ = Suite(&AuthSuite{})

func (s *AuthSuite) Test_getUser(c *C) {

	// Create a new database.
	database := &UserDatabase{
		users: map[string]*User{}}

	// Create a new user.
	user := &User{
		Username: "username",
		Password: "1234",
	}

	// Save the user in the database.
	err := database.CreateUser(user)
	c.Assert(err, IsNil)

	// Get the user from the database.
	retrievedUser, err := database.GetUser("username")

	c.Assert(err, IsNil)

	//Assert that the retrieved user is the same as the user that was created
	c.Assert(retrievedUser, DeepEquals, user)

	// Get user that does not exist.
	retrievedUser, err = database.GetUser("non-user")
	c.Assert(err, ErrorMatches, "user non existent")
	c.Assert(retrievedUser, IsNil)
}

func (s *AuthSuite) Test_validUserAndPassword(c *C) {

	database := &UserDatabase{
		users: map[string]*User{
			"employee": {
				Username: "frochina",
				Password: "2333",
			},
			"employee3": {
				Username: "laura",
				Password: "7373883",
			},
		}}

	userTest := &User{
		Username: "frochina",
		Password: "2333",
	}

	err := database.Login(userTest)
	c.Assert(err, IsNil)

}
