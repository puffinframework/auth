package auth

import (
	"github.com/puffinframework/event"
)

type VerifiedAccountEvent struct {
	Header event.Header
	Data   Verification
}

func (self *authServiceImpl) VerifyAccount(verificationToken string) error {
	sd := self.processEvents()

	verification, err := DecodeVerification(verificationToken)
	if err != nil {
		return err
	}

	if sd.GetUserId(verification.AppId, verification.Email) != verification.UserId {
		return ErrVerificationDenied
	}

	evt := VerifiedAccountEvent{
		Header: event.NewHeader("VerifiedAccount", 1),
		Data:   verification,
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func OnVerifiedAccount(evt VerifiedAccountEvent, sd SnapshotData) error {
	verification := evt.Data
	sd.SetVerification(verification)
	return nil
}
