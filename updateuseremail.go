package auth

import (
	"github.com/puffinframework/event"
)

type UpdatedUserEmailEvent ChangedEmailEvent

func (self *serviceImpl) UpdateUserEmail(userId, newEmail string) error {
	self.store.mustProcessEvents()

	evt := UpdatedUserEmailEvent{
		Header: event.NewHeader("UpdatedUserEmail", 1),
	}
	evt.Data.UserId = userId
	evt.Data.Email = newEmail

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) onUpdatedUserEmail(evt UpdatedUserEmailEvent) error {
	data := evt.Data
	self.setEmail(data.UserId, data.Email)
	return nil
}
