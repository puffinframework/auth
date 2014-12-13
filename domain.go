package auth

import (
	"github.com/puffinframework/event"
	"github.com/satori/go.uuid"
)

const (
	CREATED_USER string = "CreatedUser"
)

type User struct {
	Id    string
	AppId string
	Email string
}

type AppIdByEmail map[string]string

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func CreateUser(appId string, email string, password string, appIdByEmail AppIdByEmail) (CreatedUserEvent, error) {
	if appIdByEmail[email] == appId {
		return CreatedUserEvent{}, ErrEmailAlreadyUsed
	}

	evt := CreatedUserEvent{
		Header: event.NewHeader(CREATED_USER, 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email},
	}
	return evt, nil
}

func OnCreatedUser(evt CreatedUserEvent, appIdByEmail AppIdByEmail) error {
	user := evt.Data
	appIdByEmail[user.Email] = user.AppId
	return nil
}
