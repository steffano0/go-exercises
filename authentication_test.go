package goxes

import (
	"testing"
	"gopkg.in/check.v1"
)



type UserDatabase struct {
	users map[string]*User
}

func Test_getUser(t *testing.T) {
	c := check.New(t)

	// Create a new database.
	database := &UserDatabase{}

	// Create a new user.
	user := &User{
		Username: "username",
		Password: "1234",
	}

	// Save the user in the database.
	err := database.CreateUser(user)
	c.Assert(err, check.IsNil)
	
	// Get the user from the database.
	retrievedUser, err := database.GetUser("username")
	c.Assert(retrievedUser, check.DeepEquals, user)

	// Get user that does not exist.
	retrievedUser, err = database.GetUser ("non-user")
	c.Assert(err, check.ErrorMatches, "user non existent")
	c.Assert(retrievedUser, check.Isnil)
}

