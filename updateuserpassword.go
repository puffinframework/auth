package auth

import (
	"github.com/puffinframework/event"

	"golang.org/x/crypto/bcrypt"
)

type UpdatedUserPasswordEvent ChangedPasswordEvent

func (self *serviceImpl) UpdateUserPassword(adminToken, userId, newPassword string) error {
	self.store.mustProcessEvents()

	// TODO check adminToken

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return err
	}

	evt := UpdatedUserPasswordEvent{
		Header: event.NewHeader("UpdatedUserPassword", 1),
	}
	evt.Data.UserId = userId
	evt.Data.HashedPassword = newHashedPassword

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) OnUpdatedUserPassword(evt UpdatedUserPasswordEvent) error {
	data := evt.Data
	self.setHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
