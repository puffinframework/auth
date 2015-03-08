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

func ChangePassword(session Session, oldPassword string, newPassword string, store SnapshotStore) (ChangedPasswordEvent, error) {
	hashedPassword := store.GetHashedPassword(session.UserId)
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

func OnChangedPassword(evt ChangedPasswordEvent, store SnapshotStore) error {
	data := evt.Data
	store.SetHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
