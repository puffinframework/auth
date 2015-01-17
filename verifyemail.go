package auth

import (
	"github.com/puffinframework/event"
)

type VerifiedEmailEvent struct {
	Header event.Header
	Data   Verification
}

func VerifyEmail(verification Verification, store SnapshotStore) (VerifiedEmailEvent, error) {
	if store.GetUserId(verification.AppId, verification.Email) != verification.UserId {
		return VerifiedEmailEvent{}, ErrVerificationDenied
	}

	evt := VerifiedEmailEvent{
		Header: event.NewHeader("VerifiedEmail", 1),
		Data:   verification,
	}
	return evt, nil
}

func OnVerifiedEmail(evt VerifiedEmailEvent, store SnapshotStore) error {
	verification := evt.Data
	store.SetVerification(verification)
	return nil
}
