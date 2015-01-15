package auth

import (
	"time"

	"github.com/puffinframework/event"
	"github.com/satori/go.uuid"
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

type SignedUpEvent struct {
	Header event.Header
	Data   User
}

type SignedInEvent struct {
	Header event.Header
	Data   Session
}

type VerifiedEmailEvent struct {
	Header event.Header
	Data   Verification
}

func SignUp(appId, email, password string, snapshotData SnapshotData) (SignedUpEvent, error) {
	if snapshotData.GetUserId(appId, email) != "" {
		return SignedUpEvent{}, ErrEmailAlreadyUsed
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return SignedUpEvent{}, err
	}

	evt := SignedUpEvent{
		Header: event.NewHeader("SignedUp", 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email, HashedPassword: hashedPassword},
	}
	return evt, nil
}

func OnSignedUp(evt SignedUpEvent, snapshotData SnapshotData) error {
	user := evt.Data
	snapshotData.CreateUser(user)
	return nil
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
