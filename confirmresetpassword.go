package auth

import (
	"github.com/puffinframework/event"

	"golang.org/x/crypto/bcrypt"
)

type ConfirmedResetPasswordEvent struct {
	Header event.Header
	Data   struct {
		UserId         string
		HashedPassword []byte
	}
}

func (self *serviceImpl) ConfirmResetPassword(resetToken string, newPassword string) error {
	self.store.mustProcessEvents()

	reset, err := DecodeReset(resetToken)
	if err != nil {
		return err
	}

	storedReset, err := self.store.getReset(reset.UserId)
	if storedReset.UserId != reset.UserId || storedReset.Email != reset.Email {
		return ErrResetPasswordDenied
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return err
	}

	evt := ConfirmedResetPasswordEvent{
		Header: event.NewHeader("ConfirmedResetPassword", 1),
	}
	evt.Data.UserId = reset.UserId
	evt.Data.HashedPassword = hashedPassword

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

func (self *memStore) onConfirmedResetPassword(evt ConfirmedResetPasswordEvent) error {
	data := evt.Data
	self.delReset(data.UserId)
	self.setHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
