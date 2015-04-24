package auth

import (
	"github.com/puffinframework/event"
)

type VerifiedAccountEvent struct {
	Header event.Header
	Data   Verification
}

func (self *serviceImpl) VerifyAccount(verificationToken string) error {
	self.store.mustProcessEvents()

	verification, err := DecodeVerification(verificationToken)
	if err != nil {
		return err
	}

	user, err := self.store.getUser(verification.UserId)
	if err != nil {
		return err
	}

	if user.Id == verification.UserId && user.Email == verification.Email {
		return ErrVerificationDenied
	}

	evt := VerifiedAccountEvent{
		Header: event.NewHeader("VerifiedAccount", 1),
		Data:   verification,
	}

	self.eventStore.MustSaveEvent(evt.Header, evt.Data)
	return nil
}

/*
func (self *snapshotDataImpl) OnVerifiedAccount(evt VerifiedAccountEvent) error {
	verification := evt.Data
	self.setVerification(verification)
	return nil
}
*/
