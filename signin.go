package auth

import (
	"time"

	"github.com/puffinframework/event"
	"golang.org/x/crypto/bcrypt"
)

type SignedInEvent struct {
	Header event.Header
	Data   Session
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
		Header: event.NewHeader("SignedIn", 1),
		Data:   Session{UserId: userId, CreatedAt: time.Now()},
	}
	return evt, nil
}
