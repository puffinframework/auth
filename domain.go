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

type UserByEmail map[string]User

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

func SignUp(appId string, email string, password string, userByEmail UserByEmail) (SignedUpEvent, error) {
	if userByEmail[email].AppId == appId {
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

func OnSignedUp(evt SignedUpEvent, userByEmail UserByEmail) error {
	user := evt.Data
	userByEmail[user.Email] = user
	return nil
}

func SignIn(appId string, email string, password string, userByEmail UserByEmail) (SignedInEvent, error) {
	user := userByEmail[email]
	if err := bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password)); err != nil {
		return SignedInEvent{}, ErrSignInDenied
	}

	evt := SignedInEvent{
		Header: event.NewHeader(SIGNED_UP, 1),
		Data:   Session{Id: uuid.NewV1().String(), CreatedAt: time.Now(), UserId: user.Id},
	}
	return evt, nil
}
