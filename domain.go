package auth

import (
	"time"

	"github.com/puffinframework/event"
	"golang.org/x/crypto/bcrypt"
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

type SignedInEvent struct {
	Header event.Header
	Data   Session
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

func SignIn(appId, email, password string, snapshotData SnapshotData) (SignedInEvent, error) {
	userId := snapshotData.GetUserId(appId, email)
	hashedPassword := snapshotData.GetHashedPassword(userId)

	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)); err != nil {
		return SignedInEvent{}, ErrSignInDenied
	}

	verification := snapshotData.GetVerification(userId)
	if verification.AppId != appId || verification.Email != email {
		return SignedInEvent{}, ErrEmailNotVerified
	}

	evt := SignedInEvent{
		Header: event.NewHeader("SignedUp", 1),
		Data:   Session{UserId: userId, CreatedAt: time.Now()},
	}
	return evt, nil
}
