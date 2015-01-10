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

func SignUp(appId, email, password string, userById UserById, userIdByEmail UserIdByEmail) (SignedUpEvent, error) {
	userId := userIdByEmail[email]
	if userById[userId].AppId == appId {
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

func OnSignedUp(evt SignedUpEvent, userById UserById, userIdByEmail UserIdByEmail) error {
	user := evt.Data
	userById[user.Id] = user
	userIdByEmail[user.Email] = user.Id
	return nil
}

func VerifyEmail(appId, email, userId string, userIdByEmail UserIdByEmail) (VerifiedEmailEvent, error) {
	if userIdByEmail[email] != userId {
		return VerifiedEmailEvent{}, ErrVerificationDenied
	}

	evt := VerifiedEmailEvent{
		Header: event.NewHeader("VerifiedEmail", 1),
		Data:   Verification{AppId: appId, Email: email, UserId: userId},
	}
	return evt, nil
}

func OnVerifiedEmail(evt VerifiedEmailEvent, verificationByUserId VerificationByUserId) error {
	verification := evt.Data
	verificationByUserId[verification.UserId] = verification
	return nil
}

func SignIn(appId, email, password string, userById UserById, userIdByEmail UserIdByEmail, verificationByUserId VerificationByUserId) (SignedInEvent, error) {
	userId := userIdByEmail[email]

	user := userById[userId]
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password)); err != nil {
		return SignedInEvent{}, ErrSignInDenied
	}

	verification := verificationByUserId[userId]
	if verification.AppId != appId || verification.Email != email {
		return SignedInEvent{}, ErrEmailNotVerified
	}

	evt := SignedInEvent{
		Header: event.NewHeader("SignedUp", 1),
		Data:   Session{UserId: userId, CreatedAt: time.Now()},
	}
	return evt, nil
}
