package auth

import (
	"github.com/puffinframework/event"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type SignedUpEvent struct {
	Header event.Header
	Data   User
}

func (self *serviceImpl) SignUp(appId, email, password string) (string, error) {
	//sd := self.processEvents()

	userId, err := self.store.GetUserId(appId, email)
	if err != nil {
		return "", err
	}

	if userId != "" {
		return "", ErrEmailAlreadyUsed
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}

	evt := SignedUpEvent{
		Header: event.NewHeader("SignedUp", 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email, HashedPassword: hashedPassword},
	}

	//self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeVerification(Verification{Email: evt.Data.Email, UserId: evt.Data.Id}), nil
}

func (self *memStore) OnSignedUp(evt SignedUpEvent) error {
	user := evt.Data
	self.createUser(user)
	self.setLastEventDt(evt.Header.CreatedAt)
	return nil
}
