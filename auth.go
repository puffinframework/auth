package auth

import (
	"errors"
)

var (
	ErrEmailExists error = errors.New("auth: email exists")
)

type UsersByID map[string]*User

type User struct {
	ID         string // set to Email
	Email      string
	Hash       string
	HashedPass string
}

func CreateUser(email string, password string, usersByID UsersByID) (*User, error) {
	if usersByID[email] != nil {
		return &User{}, ErrEmailExists
	}

	user := &User{
		ID:    email,
		Email: email,
	}
	return user, nil
}
