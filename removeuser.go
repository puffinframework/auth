package auth

import (
	"github.com/puffinframework/event"
)

type RemovedUserEvent struct {
	Header event.Header
	Data   struct {
		UserId string
	}
}

func (self *serviceImpl) RemoveUser(adminToken, userId string) error {
	self.store.mustProcessEvents()

	// TODO check adminToken

	evt := RemovedUserEvent{Header: event.NewHeader("RemovedUser", 1)}
	evt.Data.UserId = userId

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) onRemovedUser(evt RemovedUserEvent) error {
	userId := evt.Data.UserId
	self.removeUser(userId)
	return nil
}
