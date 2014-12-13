package auth

import (
	"errors"
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
	"github.com/satori/go.uuid"
	"time"
)

var (
	ErrEmailUsed error = errors.New("auth: the email is already being used")
)

type User struct {
	Id    string
	AppId string
	Email string
}

type AppIdByEmail map[string]string

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func CreateUser(appId string, email string, password string, appIdByEmail AppIdByEmail) (CreatedUserEvent, error) {
	if appIdByEmail[email] == appId {
		return CreatedUserEvent{}, ErrEmailUsed
	}

	evt := CreatedUserEvent{
		Header: event.NewHeader("CreatedUser", 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email},
	}
	return evt, nil
}

func OnCreatedUser(evt CreatedUserEvent, appIdByEmail AppIdByEmail) error {
	user := evt.Data
	appIdByEmail[user.Email] = user.AppId
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
	AppIdByEmail AppIdByEmail
}

func NewAuth(es event.Store, ss snapshot.Store) Auth {
	return &authImpl{es: es, ss: ss}
}

func (self *authImpl) CreateUser(appId string, email string, password string) error {
	snapshot := &authSnapshot{}
	self.ss.MustLoadSnapshot("AuthSnapshot", snapshot)

	evt, err := CreateUser(appId, email, password, snapshot.AppIdByEmail)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authImpl) ProcessEvents() {
	snapshot := &authSnapshot{}
	self.ss.MustLoadSnapshot("AuthSnapshot", snapshot)
	self.es.ForEachEventHeader(snapshot.LastEventDt, func(header event.Header) (bool, error) {
		switch header.Type {
		case "CreatedUser":
			user := User{}
			self.es.MustLoadEventData(header, &user)
			evt := CreatedUserEvent{Header: header, Data: user}
			if err := OnCreatedUser(evt, snapshot.AppIdByEmail); err != nil {
				return false, err
			}
		}
		snapshot.LastEventDt = header.CreatedAt
		return true, nil
	})

	self.ss.MustSaveSnapshot("AuthSnapshot", snapshot)
}
