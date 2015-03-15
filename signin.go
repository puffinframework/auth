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

func SignIn(appId, email, password string, sd SnapshotData) (SignedInEvent, error) {
	userId := sd.GetUserId(appId, email)
	hashedPassword := sd.GetHashedPassword(userId)

	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)); err != nil {
		return SignedInEvent{}, ErrSignInDenied
	}

	verification := sd.GetVerification(userId)
	if verification.AppId != appId || verification.Email != email {
		return SignedInEvent{}, ErrEmailNotVerified
	}

	evt := SignedInEvent{
		Header: event.NewHeader("SignedIn", 1),
		Data:   Session{UserId: userId, CreatedAt: time.Now()},
	}
	return evt, nil
}
