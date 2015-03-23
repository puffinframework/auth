package auth

import (
	"github.com/puffinframework/event"

	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func CreateUser(session Session, authorizationId, appId, email, password string, sd SnapshotData) (CreatedUserEvent, error) {
	// TODO check authorization

	if sd.GetUserId(appId, email) != "" {
		return CreatedUserEvent{}, ErrEmailAlreadyUsed
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return CreatedUserEvent{}, err
	}

	evt := CreatedUserEvent{
		Header: event.NewHeader("CreatedUser", 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email, HashedPassword: hashedPassword},
	}

	return evt, nil
}

func OnCreatedUser(evt CreatedUserEvent, sd SnapshotData) error {
	user := evt.Data
	sd.CreateUser(user)

	verification := Verification{AppId: user.AppId, Email: user.Email, UserId: user.Id}
	sd.SetVerification(verification)

	return nil
}
