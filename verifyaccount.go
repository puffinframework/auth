package auth

import (
	"github.com/puffinframework/event"
)

type VerifiedAccountEvent struct {
	Header event.Header
	Data   Verification
}

func VerifyAccount(verification Verification, store SnapshotStore) (VerifiedAccountEvent, error) {
	if store.GetUserId(verification.AppId, verification.Email) != verification.UserId {
		return VerifiedAccountEvent{}, ErrVerificationDenied
	}

	evt := VerifiedAccountEvent{
		Header: event.NewHeader("VerifiedAccount", 1),
		Data:   verification,
	}
	return evt, nil
}

func OnVerifiedAccount(evt VerifiedAccountEvent, store SnapshotStore) error {
	verification := evt.Data
	store.SetVerification(verification)
	return nil
}
