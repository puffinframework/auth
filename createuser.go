package auth

import (
	"github.com/puffinframework/event"

	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func (self *authServiceImpl) CreateUser(sessionToken, authorizationId, appId, email, password string) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	authorization := sd.GetUserAuthorization(session.UserId, authorizationId)
	if !sd.IsSuperUser(session.UserId) || authorization.UserId == "" || !authorization.IsAuthorized {
		return ErrNotAuthorized
	}

	if sd.GetUserId(appId, email) != "" {
		return ErrEmailAlreadyUsed
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return err
	}

	evt := CreatedUserEvent{
		Header: event.NewHeader("CreatedUser", 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email, HashedPassword: hashedPassword},
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *snapshotDataImpl) OnCreatedUser(evt CreatedUserEvent) error {
	user := evt.Data
	self.createUser(user)
	self.setVerificationForUser(user)
	return nil
}
