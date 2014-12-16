package auth

import (
	"github.com/puffinframework/event"
	"github.com/satori/go.uuid"
)

const (
	SIGNED_UP string = "SignedUp"
)

type User struct {
	Id    string
	AppId string
	Email string
}

type AppIdByEmail map[string]string

type SignedUpEvent struct {
	Header event.Header
	Data   User
}

func SignUp(appId string, email string, password string, appIdByEmail AppIdByEmail) (SignedUpEvent, error) {
	if appIdByEmail[email] == appId {
		return SignedUpEvent{}, ErrEmailAlreadyUsed
	}

	evt := SignedUpEvent{
		Header: event.NewHeader(SIGNED_UP, 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email},
	}
	return evt, nil
}

func OnSignedUp(evt SignedUpEvent, appIdByEmail AppIdByEmail) error {
	user := evt.Data
	appIdByEmail[user.Email] = user.AppId
	return nil
}
