package goxes

import (
	"errors"
	
)


type Authentication interface {
	GetUser(username string) (*User, error)
	CreateUser(username string, password string)
	Login(User)

}

type UserDatabase struct {
	users map[string]*User
}



type User struct {
	Username string
	Password string
}

func (database *UserDatabase) GetUser(username string) (*User, error) {
	if user, ok := database.users[username]; ok {
		return user, nil 
	}

	return nil, errors.New("user non existent")
}

func (database *UserDatabase) CreateUser(user *User) error {
	if database.users[user.Username] != nil {
		return errors.New("user already exists")
	}
	
	database.users[user.Username] = user 
	return nil
}

func (database *UserDatabase) Login(userEval *User) error {


	for _, user := range database.users {


		if user.Username == userEval.Username && user.Password == userEval.Password {
			
			return nil
		}
		
	}
	return errors.New("user not authorized")
}