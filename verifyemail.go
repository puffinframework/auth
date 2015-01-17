package auth

import (
	"github.com/puffinframework/event"
)

type VerifiedEmailEvent struct {
	Header event.Header
	Data   Verification
}

func VerifyEmail(appId, email, userId string, snapshotData SnapshotData) (VerifiedEmailEvent, error) {
	if snapshotData.GetUserId(appId, email) != userId {
		return VerifiedEmailEvent{}, ErrVerificationDenied
	}

	evt := VerifiedEmailEvent{
		Header: event.NewHeader("VerifiedEmail", 1),
		Data:   Verification{AppId: appId, Email: email, UserId: userId},
	}
	return evt, nil
}

func OnVerifiedEmail(evt VerifiedEmailEvent, snapshotData SnapshotData) error {
	verification := evt.Data
	snapshotData.SetVerification(verification)
	return nil
}

