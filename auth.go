package auth

import (
	"time"

	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
)

const (
	AUTH_SNAPSHOT string = "AUTH_SNAPSHOT"
)

type Auth interface {
	SignUp(appId, email, password string) (userId string, err error)
	SignIn(appId, email, password string) (sessionToken string, err error)
	VerifyEmail(appId, email, userId string) error
	//ResetPassword(resetToken string) error
	//ChangePassword(sessionToken, oldPassword, newPassword string) error
}

type authImpl struct {
	es event.Store
	ss snapshot.Store
}

func NewAuth(es event.Store, ss snapshot.Store) Auth {
	return &authImpl{es: es, ss: ss}
}

type snapshotData struct {
	LastEventDt          time.Time
	UserById             UserById
	UserIdByEmail        UserIdByEmail
	VerificationByUserId VerificationByUserId
}

func (self *authImpl) SignUp(appId, email, password string) (userId string, err error) {
	data := self.processEvents()

	evt, err := SignUp(appId, email, password, data.UserById, data.UserIdByEmail)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return evt.Data.Id, nil
}

func (self *authImpl) VerifyEmail(appId, email, userId string) error {
	data := self.processEvents()

	evt, err := VerifyEmail(appId, email, userId, data.UserIdByEmail)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authImpl) SignIn(appId, email, password string) (sessionToken string, err error) {
	data := self.processEvents()

	evt, err := SignIn(appId, email, password, data.UserById, data.UserIdByEmail, data.VerificationByUserId)
	if err != nil {
		return sessionToken, err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeSession(evt.Data), nil
}

func (self *authImpl) processEvents() *snapshotData {
	data := &snapshotData{}
	self.ss.MustLoadSnapshot(AUTH_SNAPSHOT, data)

	self.es.ForEachEventHeader(data.LastEventDt, func(header event.Header) (bool, error) {
		data.LastEventDt = header.CreatedAt
		var err error
		switch header.Type {
		case SIGNED_UP:
			user := User{}
			self.es.MustLoadEventData(header, &user)
			evt := SignedUpEvent{Header: header, Data: user}
			err = OnSignedUp(evt, data.UserById, data.UserIdByEmail)
		case VERIFIED_EMAIL:
			verification := Verification{}
			self.es.MustLoadEventData(header, &verification)
			evt := VerifiedEmailEvent{Header: header, Data: verification}
			err = OnVerifiedEmail(evt, data.VerificationByUserId)
		}
		return err == nil, err
	})

	self.ss.MustSaveSnapshot(AUTH_SNAPSHOT, data)
	return data
}
