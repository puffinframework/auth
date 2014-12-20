package auth

import (
	"time"

	"github.com/puffinframework/event"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	SIGNED_UP string = "SignedUp"
	SIGNED_IN string = "SignedIn"
)

type User struct {
	Id             string
	AppId          string
	Email          string
	HashedPassword []byte
}

type AppIdByEmail map[string]string

type HashedPasswordByEmail map[string][]byte

type Session struct {
	Id        string
	UserId    string
	CreatedAt time.Time
}

type SessionById map[string]Session

type SignedUpEvent struct {
	Header event.Header
	Data   User
}

type SignedInEvent struct {
	Header event.Header
	Data   Session
}

func SignUp(appId string, email string, password string, appIdByEmail AppIdByEmail) (SignedUpEvent, error) {
	if appIdByEmail[email] == appId {
		return SignedUpEvent{}, ErrEmailAlreadyUsed
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return SignedUpEvent{}, err
	}

	evt := SignedUpEvent{
		Header: event.NewHeader(SIGNED_UP, 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email, HashedPassword: hashedPassword},
	}
	return evt, nil
}

func OnSignedUp(evt SignedUpEvent, appIdByEmail AppIdByEmail, hashedPasswordByEmail HashedPasswordByEmail) error {
	user := evt.Data
	appIdByEmail[user.Email] = user.AppId
	hashedPasswordByEmail[user.Email] = user.HashedPassword
	return nil
}

func SignIn(appId string, email string, password string, hashedPasswordByEmail HashedPasswordByEmail) (SignedInEvent, error) {
	if err := bcrypt.CompareHashAndPassword(hashedPasswordByEmail[email], []byte(password)); err != nil {
		return SignedInEvent{}, ErrSignInDenied
	}

	evt := SignedInEvent{
		Header: event.NewHeader(SIGNED_UP, 1),
		Data:   Session{Id: uuid.NewV1().String()},
	}
	return evt, nil
}
