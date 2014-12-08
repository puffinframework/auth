package auth

import (
	"errors"
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
	"time"
)

var (
	ErrEmailExists error = errors.New("auth: email exists")
)

type UsedEmailsMap map[string]bool

type UsersByID map[string]User

type User struct {
	Id         string
	Email      string
	Hash       string
	HashedPass string
}

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func CreateUser(email string, password string, emailsMap UsedEmailsMap) (CreatedUserEvent, error) {
	if emailsMap[email] != nil {
		return CreatedUserEvent{}, ErrEmailExists
	}

	evt := CreatedUserEvent{
		Header: event.NewEvent("CreatedUser", 1),
		Data:   User{Id: email, Email: email},
	}
	return evt, nil
}
