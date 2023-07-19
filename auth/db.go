package auth

import (
	"errors"
)

type Database interface {
	GetUser(string) (User, error)
	AddUser(User) error
}

type User interface {
	GetUsername() string
	GetPassword() string
}

type simpleUserDatabase struct {
	users map[string]User
}

type user struct {
	username string
	password string
}

func NewDatabase() Database {
	return &simpleUserDatabase{users: map[string]User{}}
}

func NewUser(username, password string) User {
	return &user{username, password}
}

func (u *user) GetUsername() string {
	return u.username
}

func (u *user) GetPassword() string {
	return u.password
}

func (d *simpleUserDatabase) GetUser(username string) (User, error) {
	if user, ok := d.users[username]; ok {
		return user, nil
	}

	return nil, errors.New("user non existent")
}

func (d *simpleUserDatabase) AddUser(u User) error {
	if d.users[u.GetUsername()] != nil {
		return errors.New("user already exists")
	}

	d.users[u.GetUsername()] = u
	return nil
}
