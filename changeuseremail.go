package auth

/*
import (
	"github.com/puffinframework/event"
)

type ChangedUserEmailEvent ChangedEmailEvent

func (self *authServiceImpl) ChangeUserEmail(sessionToken, authorizationId, userId, newEmail string) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	authorization := sd.GetUserAuthorization(session.UserId, authorizationId)
	if !authorization.IsAuthorized {
		return ErrNotAuthorized
	}

	evt := ChangedUserEmailEvent{
		Header: event.NewHeader("ChangedEmail", 1),
	}
	evt.Data.UserId = session.UserId
	evt.Data.Email = newEmail

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *snapshotDataImpl) OnChangedUserEmail(evt ChangedUserEmailEvent) error {
	data := evt.Data
	self.setEmail(data.UserId, data.Email)
	return nil
}
*/
