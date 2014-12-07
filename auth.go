package auth

import (
	"fmt"
)

type UsersByID map[string]*User

type User struct {
	ID         string
	Email      string
	Hash       string
	HashedPass string
}

func SignUp(email string, password string, usersByID UsersByID) error {
	if usersByID[email] != nil {
		return fmt.Errorf("Email exists.")
	}

	usersByID[email] = &User{
		ID:    email,
		Email: email,
	}
	return nil
}
