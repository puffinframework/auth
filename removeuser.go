package auth

/*
import (
	"github.com/puffinframework/event"
)

type RemovedUserEvent struct {
	Header event.Header
	Data   struct {
		UserId string
	}
}

func (self *authServiceImpl) RemoveUser(sessionToken, authorizationId, userId string) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	authorization := sd.GetUserAuthorization(session.UserId, authorizationId)
	if !authorization.IsAuthorized {
		return ErrNotAuthorized
	}

	evt := RemovedUserEvent{Header: event.NewHeader("RemovedUser", 1)}
	evt.Data.UserId = userId

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *snapshotDataImpl) OnRemovedUser(evt RemovedUserEvent) error {
	userId := evt.Data.UserId
	self.removeUser(userId)
	return nil
}
*/
