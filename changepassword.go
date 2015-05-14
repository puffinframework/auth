package auth

import (
	"github.com/puffinframework/event"

	"golang.org/x/crypto/bcrypt"
)

type ChangedPasswordEvent struct {
	Header event.Header
	Data   struct {
		UserId         string
		HashedPassword []byte
	}
}

func (self *serviceImpl) ChangePassword(sessionToken, oldPassword, newPassword string) error {
	self.store.mustProcessEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	hashedPassword, err := self.store.getHashedPassword(session.UserId)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(oldPassword)); err != nil {
		return ErrChangePasswordDenied
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return err
	}

	evt := ChangedPasswordEvent{
		Header: event.NewHeader("ChangedPassword", 1),
	}
	evt.Data.UserId = session.UserId
	evt.Data.HashedPassword = newHashedPassword

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) onChangedPassword(evt ChangedPasswordEvent) error {
	data := evt.Data
	self.setHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
