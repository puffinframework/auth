package auth

import (
	"time"

	"github.com/puffinframework/event"
)

type User struct {
	Id             string
	AppId          string
	Email          string
	HashedPassword []byte
}

type Session struct {
	UserId    string
	CreatedAt time.Time
}
type Verification struct {
	UserId string
	AppId  string
	Email  string
}

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

