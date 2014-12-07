package auth

import (
	"errors"
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
	"time"
)

type Snapshot struct {
	seqNum    time.Time
	usersByID UsersByID
}

type UsersByID map[string]*User

type User struct {
	ID         string // set to Email
	Email      string
	Hash       string
	HashedPass string
}

type CreatedUserEventData struct {
	Data User
}

var (
	ErrEmailExists error = errors.New("auth: email exists")
)

type Auth struct {
	es *event.Store
	ss *snapshot.Store
}

func (self *Auth) CreateUser(email string, password string, usersByID UsersByID) (CreatedUserEventData, error) {
	if usersByID[email] != nil {
		return CreatedUserEventData{}, ErrEmailExists
	}

	ed := CreatedUserEventData{
		Data: User{
			ID:    email,
			Email: email,
		},
	}
	return ed, nil
}
