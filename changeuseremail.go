package auth

import (
	"github.com/puffinframework/event"
)

type UpdatedUserEmailEvent ChangedEmailEvent

func (self *serviceImpl) UpdateUserEmail(adminToken, userId, newEmail string) error {
	self.store.mustProcessEvents()

	// TODO check adminToken

	evt := UpdatedUserEmailEvent{
		Header: event.NewHeader("UpdatedUserEmail", 1),
	}
	evt.Data.UserId = userId
	evt.Data.Email = newEmail

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) OnUpdatedUserEmail(evt UpdatedUserEmailEvent) error {
	data := evt.Data
	self.setEmail(data.UserId, data.Email)
	return nil
}
