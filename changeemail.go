package auth

import (
	"github.com/puffinframework/event"
)

type ChangedEmailEvent struct {
	Header event.Header
	Data   ChangedEmailEventData
}

type ChangedEmailEventData struct {
	UserId string
	Email  string
}

func (self *authServiceImpl) ChangeEmail(sessionToken, newEmail string) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	appId := sd.GetAppId(session.UserId)
	if sd.GetUserId(appId, newEmail) != "" {
		return ErrEmailAlreadyUsed
	}

	evt := ChangedEmailEvent{
		Header: event.NewHeader("ChangedEmail", 1),
	}
	evt.Data.UserId = session.UserId
	evt.Data.Email = newEmail

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *snapshotDataImpl) OnChangedEmail(evt ChangedEmailEvent) error {
	data := evt.Data
	self.setEmail(data.UserId, data.Email)
	return nil
}
