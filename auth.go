package auth

import (
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
)

type AuthService interface {
	SignUp(appId, email, password string) (verificationToken string, err error)
	SignIn(appId, email, password string) (sessionToken string, err error)
	VerifyEmail(verificationToken string) error
	//ResetPassword(resetToken string) error
	//ChangePassword(sessionToken, oldPassword, newPassword string) error
}

type implAuthService struct {
	es event.Store
	ss snapshot.Store
}

func NewAuthService(es event.Store, ss snapshot.Store) AuthService {
	return &implAuthService{es: es, ss: ss}
}

func (self *implAuthService) SignUp(appId, email, password string) (verificationToken string, err error) {
	store := self.processEvents()

	evt, err := SignUp(appId, email, password, store)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeVerification(Verification{AppId: evt.Data.AppId, Email: evt.Data.Email, UserId: evt.Data.Id}), nil
}

func (self *implAuthService) VerifyEmail(verificationToken string) error {
	store := self.processEvents()

	verification, err := DecodeVerification(verificationToken)
	if err != nil {
		return err
	}

	evt, err := VerifyEmail(verification, store)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *implAuthService) SignIn(appId, email, password string) (sessionToken string, err error) {
	store := self.processEvents()

	evt, err := SignIn(appId, email, password, store)
	if err != nil {
		return sessionToken, err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeSession(evt.Data), nil
}

func (self *implAuthService) processEvents() SnapshotStore {
	store := NewSnapshotStore(self.ss)
	store.Load()

	self.es.ForEachEventHeader(store.GetLastEventDt(), func(header event.Header) (bool, error) {
		store.SetLastEventDt(header.CreatedAt)
		var err error
		switch header.Type {
		case "SignedUp":
			user := User{}
			self.es.MustLoadEventData(header, &user)
			evt := SignedUpEvent{Header: header, Data: user}
			err = OnSignedUp(evt, store)
		case "VerifiedEmail":
			verification := Verification{}
			self.es.MustLoadEventData(header, &verification)
			evt := VerifiedEmailEvent{Header: header, Data: verification}
			err = OnVerifiedEmail(evt, store)
		}
		return err == nil, err
	})

	store.Save()
	return store
}
