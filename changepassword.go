package auth

import (
	"github.com/puffinframework/event"
	"golang.org/x/crypto/bcrypt"
)

type ChangedPasswordEvent struct {
	Header event.Header
	Data   ChangedPasswordEventData
}

type ChangedPasswordEventData struct {
	UserId         string
	HashedPassword []byte
}

type ChangedUserPasswordEvent ChangedPasswordEvent

func ChangePassword(session Session, oldPassword string, newPassword string, sd SnapshotData) (ChangedPasswordEvent, error) {
	hashedPassword := sd.GetHashedPassword(session.UserId)
	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(oldPassword)); err != nil {
		return ChangedPasswordEvent{}, ErrChangePasswordDenied
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return ChangedPasswordEvent{}, err
	}

	evt := ChangedPasswordEvent{
		Header: event.NewHeader("ChangedPassword", 1),
	}
	evt.Data.UserId = session.UserId
	evt.Data.HashedPassword = newHashedPassword
	return evt, nil
}

func OnChangedPassword(evt ChangedPasswordEvent, sd SnapshotData) error {
	data := evt.Data
	sd.SetHashedPassword(data.UserId, data.HashedPassword)
	return nil
}

func ChangeUserPassword(session Session, authorizationId string, userId string, newPassword string, sd SnapshotData) (ChangedUserPasswordEvent, error) {
	authorization := sd.GetUserAuthorization(session.UserId, authorizationId)
	if !sd.IsSuperUser(session.UserId) || authorization.UserId == "" || !authorization.IsAuthorized {
		return ChangedUserPasswordEvent{}, ErrNotAuthorized
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return ChangedUserPasswordEvent{}, err
	}

	evt := ChangedUserPasswordEvent{
		Header: event.NewHeader("ChangedPassword", 1),
	}
	evt.Data.UserId = session.UserId
	evt.Data.HashedPassword = newHashedPassword
	return evt, nil
}

func OnChangedUserPassword(evt ChangedUserPasswordEvent, sd SnapshotData) error {
	data := evt.Data
	sd.SetHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
