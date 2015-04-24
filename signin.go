package auth

import (
	"time"

	"github.com/puffinframework/event"
	"golang.org/x/crypto/bcrypt"
)

type SignedInEvent struct {
	Header event.Header
	Data   Session
}

func (self *serviceImpl) SignIn(appId, email, password string) (sessionToken string, err error) {
	self.store.mustProcessEvents()

	userId, err := self.store.getUserId(appId, email)
	if err != nil {
		return "", err
	}

	hashedPassword, err := self.store.getHashedPassword(userId)
	if err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)); err != nil {
		return "", ErrSignInDenied
	}

	verification, err := self.store.getVerification(userId)
	if err != nil {
		return "", err
	}

	if verification.UserId != userId || verification.Email != email {
		return "", ErrEmailNotVerified
	}

	evt := SignedInEvent{
		Header: event.NewHeader("SignedIn", 1),
		Data:   Session{UserId: userId, CreatedAt: time.Now()},
	}

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return EncodeSession(evt.Data), nil
}
