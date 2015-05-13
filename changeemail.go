package auth

import (
	"github.com/puffinframework/event"
)

type ChangedEmailEvent struct {
	Header event.Header
	Data   struct {
		UserId string
		Email  string
	}
}

func (self *serviceImpl) ChangeEmail(sessionToken, newEmail string) error {
	self.store.mustProcessEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	appId, err := self.store.getAppId(session.UserId)
	if err != nil {
		return err
	}

	userId, err := self.store.getUserId(appId, newEmail)
	if err != nil {
		return err
	}
	if userId != "" {
		return ErrEmailAlreadyUsed
	}

	evt := ChangedEmailEvent{
		Header: event.NewHeader("ChangedEmail", 1),
	}
	evt.Data.UserId = session.UserId
	evt.Data.Email = newEmail

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) onChangedEmail(evt ChangedEmailEvent) error {
	data := evt.Data
	self.setEmail(data.UserId, data.Email)
	return nil
}
