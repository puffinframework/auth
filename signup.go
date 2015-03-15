package auth

import (
	"github.com/puffinframework/event"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type SignedUpEvent struct {
	Header event.Header
	Data   User
}

func SignUp(appId, email, password string, sd SnapshotData) (SignedUpEvent, error) {
	if sd.GetUserId(appId, email) != "" {
		return SignedUpEvent{}, ErrEmailAlreadyUsed
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return SignedUpEvent{}, err
	}

	evt := SignedUpEvent{
		Header: event.NewHeader("SignedUp", 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email, HashedPassword: hashedPassword},
	}
	return evt, nil
}

func OnSignedUp(evt SignedUpEvent, sd SnapshotData) error {
	user := evt.Data
	sd.CreateUser(user)
	return nil
}
