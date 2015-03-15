package auth

import (
	"github.com/puffinframework/event"
)

type VerifiedAccountEvent struct {
	Header event.Header
	Data   Verification
}

func VerifyAccount(verification Verification, sd SnapshotData) (VerifiedAccountEvent, error) {
	if sd.GetUserId(verification.AppId, verification.Email) != verification.UserId {
		return VerifiedAccountEvent{}, ErrVerificationDenied
	}

	evt := VerifiedAccountEvent{
		Header: event.NewHeader("VerifiedAccount", 1),
		Data:   verification,
	}
	return evt, nil
}

func OnVerifiedAccount(evt VerifiedAccountEvent, sd SnapshotData) error {
	verification := evt.Data
	sd.SetVerification(verification)
	return nil
}
