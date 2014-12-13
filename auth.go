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
	CreateUser(appId string, email string, password string) error
}

type authImpl struct {
	es event.Store
	ss snapshot.Store
}

type snapshotData struct {
	LastEventDt  time.Time
	AppIdByEmail AppIdByEmail
}

func NewAuth(es event.Store, ss snapshot.Store) Auth {
	return &authImpl{es: es, ss: ss}
}

func (self *authImpl) CreateUser(appId string, email string, password string) error {
	data := self.processEvents()

	evt, err := CreateUser(appId, email, password, data.AppIdByEmail)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authImpl) processEvents() *snapshotData {
	data := &snapshotData{}
	self.ss.MustLoadSnapshot(AUTH_SNAPSHOT, data)

	self.es.ForEachEventHeader(data.LastEventDt, func(header event.Header) (bool, error) {
		switch header.Type {
		case "CreatedUser":
			user := User{}
			self.es.MustLoadEventData(header, &user)
			evt := CreatedUserEvent{Header: header, Data: user}
			if err := OnCreatedUser(evt, data.AppIdByEmail); err != nil {
				return false, err
			}
		}
		data.LastEventDt = header.CreatedAt
		return true, nil
	})

	self.ss.MustSaveSnapshot(AUTH_SNAPSHOT, data)
	return data
}
