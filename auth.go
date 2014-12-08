package auth

import (
	"errors"
	"github.com/puffinframework/event"
)

var (
	ErrEmailUsed error = errors.New("auth: the email is already being used")
)

type User struct {
	AppId      string
	Id         string
	Email      string
	Hash       string
	HashedPass string
}

type UsersById map[string]User

type AppIdByEmail map[string]string

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func CreateUser(appId string, email string, password string, appIdByEmail AppIdByEmail) (CreatedUserEvent, error) {
	if appIdByEmail[email] == appId {
		return CreatedUserEvent{}, ErrEmailUsed
	}

	evt := CreatedUserEvent{
		Header: event.NewHeader("CreatedUser", 1),
		Data:   User{AppId: appId, Id: email, Email: email},
	}
	return evt, nil
}

func OnCreatedUser(evt CreatedUserEvent, appIdByEmail AppIdByEmail, usersById UsersById) error {
	user := evt.Data
	appIdByEmail[user.Email] = user.AppId
	usersById[user.Id] = user
	return nil
}
