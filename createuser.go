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

func (self *serviceImpl) CreateUser(adminToken, appId, email, password string) error {
	self.store.mustProcessEvents()

	// TODO check adminToken

	userId, err := self.store.getUserId(appId, email)
	if err != nil {
		return err
	}

	if userId != "" {
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

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) onCreatedUser(evt CreatedUserEvent) error {
	user := evt.Data
	self.createUser(user)
	self.setVerificationForUser(user)
	return nil
}
