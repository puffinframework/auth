package auth

import (
	"errors"
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
	"time"
)

var (
	ErrEmailUsed error = errors.New("auth: the email is already being used")
)

type User struct {
	AppId      string
	Id         string
	Email      string
	Hash       string
	HashedPass string
}

type UsersById map[string]User

type UserIdByEmail map[string]string

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func CreateUser(appId string, email string, password string, userIdByEmail UserIdByEmail) (CreatedUserEvent, error) {
	if userIdByEmail[email] == appId {
		return CreatedUserEvent{}, ErrEmailUsed
	}

	evt := CreatedUserEvent{
		Header: event.NewHeader("CreatedUser", 1),
		Data:   User{AppId: appId, Id: email, Email: email},
	}
	return evt, nil
}

func OnCreatedUser(evt CreatedUserEvent, userIdByEmail UserIdByEmail, usersById UsersById) error {
	user := evt.Data
	userIdByEmail[user.Email] = user.AppId
	usersById[user.Id] = user
	return nil
}

type Auth interface {
	CreateUser(appId string, email string, password string) error
}

type authImpl struct {
	es event.Store
	ss snapshot.Store
}

type authSnapshot struct {
	LastEventDt  time.Time
	UserIdByEmail UserIdByEmail
	UsersById    UsersById
}

func NewAuth(es event.Store, ss snapshot.Store) Auth {
	return &authImpl{es: es, ss: ss}
}

func (self *authImpl) CreateUser(appId string, email string, password string) error {
	snapshot := &authSnapshot{}
	self.ss.MustLoadSnapshot("AuthSnapshot", snapshot)

	evt, err := CreateUser(appId, email, password, snapshot.UserIdByEmail)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authImpl) ProcessEvents() {
	snapshot := &authSnapshot{}
	self.ss.MustLoadSnapshot("AuthSnapshot", snapshot)
	self.es.ForEachEventHeader(snapshot.LastEventDt, func(header event.Header) bool {
		switch header.Type {
		case "CreatedUser":
			user := User{}
			self.es.MustLoadEventData(header, &user)
			/* err := */ OnCreatedUser(CreatedUserEvent{Header: header, Data: user}, snapshot.UserIdByEmail, snapshot.UsersById)
		}
		snapshot.LastEventDt = header.CreatedAt
		return true
	})
	self.ss.MustSaveSnapshot("AuthSnapshot", snapshot)
}
