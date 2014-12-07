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

type CreatedUserEventData struct {
	Data User
}

func CreateUser(email string, password string, usersByID UsersByID) (CreatedUserEventData, error) {
	if usersByID[email] != nil {
		return CreatedUserEventData{}, ErrEmailExists
	}

	ed := CreatedUserEventData{
		Data: User{
			ID:    email,
			Email: email,
		},
	}
	return ed, nil
}
