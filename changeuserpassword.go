package auth

import (
	"github.com/puffinframework/event"

	"golang.org/x/crypto/bcrypt"
)

type ChangedUserPasswordEvent ChangedPasswordEvent

func (self *authServiceImpl) ChangeUserPassword(sessionToken, authorizationId, userId, newPassword string) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	authorization := sd.GetUserAuthorization(session.UserId, authorizationId)
	if !sd.IsSuperUser(session.UserId) || authorization.UserId == "" || !authorization.IsAuthorized {
		return ErrNotAuthorized
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return err
	}

	evt := ChangedUserPasswordEvent{
		Header: event.NewHeader("ChangedPassword", 1),
	}
	evt.Data.UserId = session.UserId
	evt.Data.HashedPassword = newHashedPassword

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func OnChangedUserPassword(evt ChangedUserPasswordEvent, sd SnapshotData) error {
	data := evt.Data
	sd.SetHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
