package auth

import (
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
	"time"
)

const (
	AUTH_SNAPSHOT string = "AUTH_SNAPSHOT"
)

type Auth interface {
	SignUp(appId string, email string, password string) (userId string, err error)
	ConfirmSignUp(appId string, email string, password string) (userId string, err error)
	SignIn(appId string, email string, password string) (*Session, error)
}

type authImpl struct {
	es event.Store
	ss snapshot.Store
}

type snapshotData struct {
	LastEventDt   time.Time
	UserById      UserById
	UserIdByEmail UserIdByEmail
}

func NewAuth(es event.Store, ss snapshot.Store) Auth {
	return &authImpl{es: es, ss: ss}
}

func (self *authImpl) SignUp(appId string, email string, password string) (userId string, err error) {
	data := self.processEvents()

	evt, err := SignUp(appId, email, password, data.UserById, data.UserIdByEmail)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	userId = evt.Data.Id
	return
}

func (self *authImpl) ConfirmSignUp(appId string, email string, password string) (userId string, err error) {
	// TODO
	return "", nil
}

func (self *authImpl) SignIn(appId string, email string, password string) (*Session, error) {
	data := self.processEvents()

	evt, err := SignIn(appId, email, password, data.UserById, data.UserIdByEmail)
	if err != nil {
		return &Session{}, err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return &evt.Data, nil
}

func (self *authImpl) processEvents() *snapshotData {
	data := &snapshotData{}
	self.ss.MustLoadSnapshot(AUTH_SNAPSHOT, data)

	self.es.ForEachEventHeader(data.LastEventDt, func(header event.Header) (bool, error) {
		switch header.Type {
		case SIGNED_UP:
			user := User{}
			self.es.MustLoadEventData(header, &user)
			evt := SignedUpEvent{Header: header, Data: user}
			if err := OnSignedUp(evt, data.UserById, data.UserIdByEmail); err != nil {
				return false, err
			}
		}
		data.LastEventDt = header.CreatedAt
		return true, nil
	})

	self.ss.MustSaveSnapshot(AUTH_SNAPSHOT, data)
	return data
}
