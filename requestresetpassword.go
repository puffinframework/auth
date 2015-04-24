package auth

import (
	"time"

	"github.com/puffinframework/event"
)

type RequestedResetPasswordEvent struct {
	Header event.Header
	Data   Reset
}

func (self *serviceImpl) RequestResetPassword(appId, email string) (resetToken string, err error) {
	self.store.mustProcessEvents()

	userId, err := self.store.getUserId(appId, email)
	if err != nil {
		return "", err
	}

	verification, err := self.store.getVerification(userId)
	if err != nil {
		return "", err
	}

	if verification.UserId != userId || verification.Email != email {
		return "", ErrEmailNotVerified
	}

	evt := RequestedResetPasswordEvent{
		Header: event.NewHeader("RequestedResetPassword", 1),
		Data: Reset{
			Email:     email,
			UserId:    userId,
			CreatedAt: time.Now(),
		},
	}

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return EncodeReset(evt.Data), nil
}

func (self *memStore) onRequestedResetPassword(evt RequestedResetPasswordEvent) error {
	reset := evt.Data
	self.setReset(reset)
	return nil
}
