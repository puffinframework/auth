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
	AppId      string
	Id         string
	Email      string
	Hash       string
	HashedPass string
}

type UserById map[string]User

type UserIdByEmail map[string]string

type CreatedUserEvent struct {
	Header event.Header
	Data   User
}

func CreateUser(appId string, email string, password string, userById UserById, userIdByEmail UserIdByEmail) (CreatedUserEvent, error) {
	otherId := userIdByEmail[email]
	otherUser := userById[otherId]
	if otherUser.AppId == appId {
		return CreatedUserEvent{}, ErrEmailUsed
	}

	evt := CreatedUserEvent{
		Header: event.NewHeader("CreatedUser", 1),
		Data:   User{AppId: appId, Id: uuid.NewV1().String(), Email: email},
	}
	return evt, nil
}

func OnCreatedUser(evt CreatedUserEvent, userById UserById, userIdByEmail UserIdByEmail) error {
	user := evt.Data
	userById[user.Id] = user
	userIdByEmail[user.Email] = user.Id
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
	LastEventDt   time.Time
	UserIdByEmail UserIdByEmail
	UserById     UserById
}

func NewAuth(es event.Store, ss snapshot.Store) Auth {
	return &authImpl{es: es, ss: ss}
}

func (self *authImpl) CreateUser(appId string, email string, password string) error {
	snapshot := &authSnapshot{}
	self.ss.MustLoadSnapshot("AuthSnapshot", snapshot)

	evt, err := CreateUser(appId, email, password, snapshot.UserById, snapshot.UserIdByEmail)
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
			/* err := */ OnCreatedUser(CreatedUserEvent{Header: header, Data: user}, snapshot.UserById, snapshot.UserIdByEmail)
		}
		snapshot.LastEventDt = header.CreatedAt
		return true
	})
	self.ss.MustSaveSnapshot("AuthSnapshot", snapshot)
}
