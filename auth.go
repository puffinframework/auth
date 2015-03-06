package auth

import (
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
)

type AuthService interface {
	SignUp(appId, email, password string) (verificationToken string, err error)
	SignIn(appId, email, password string) (sessionToken string, err error)
	VerifyAccount(verificationToken string) error
	RequestReset(appId, email string) (resetToken string, err error)
	ConfirmReset(resetToken string, newPassword string) error
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

func (self *implAuthService) VerifyAccount(verificationToken string) error {
	store := self.processEvents()

	verification, err := DecodeVerification(verificationToken)
	if err != nil {
		return err
	}

	evt, err := VerifyAccount(verification, store)
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

func (self *implAuthService) RequestReset(appId, email string) (resetToken string, err error) {
	store := self.processEvents()

	evt, err := RequestReset(appId, email, store)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeReset(evt.Data), nil
}

func (self *implAuthService) ConfirmReset(resetToken string, newPassword string) error {
	store := self.processEvents()

	reset, err := DecodeReset(resetToken)
	if err != nil {
		return err
	}

	evt, err := ConfirmReset(reset, newPassword, store)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *implAuthService) processEvents() SnapshotStore {
	store := NewSnapshotStore(self.ss)
	store.Load()

	self.es.ForEachEventHeader(store.GetLastEventDt(), func(header event.Header) (bool, error) {
		store.SetLastEventDt(header.CreatedAt)
		var err error
		switch header.Type {
		case "SignedUp":
			data := User{}
			self.es.MustLoadEventData(header, &data)
			evt := SignedUpEvent{Header: header, Data: data}
			err = OnSignedUp(evt, store)
		case "VerifiedAccount":
			data := Verification{}
			self.es.MustLoadEventData(header, &data)
			evt := VerifiedAccountEvent{Header: header, Data: data}
			err = OnVerifiedAccount(evt, store)
		case "RequestedReset":
			data := Reset{}
			self.es.MustLoadEventData(header, &data)
			evt := RequestedResetEvent{Header: header, Data: data}
			err = OnRequestedReset(evt, store)
		case "ConfirmedReset":
			data := ConfirmedResetEventData{}
			self.es.MustLoadEventData(header, &data)
			evt := ConfirmedResetEvent{Header: header, Data: data}
			err = OnConfirmedReset(evt, store)
		}
		return err == nil, err
	})

	store.Save()
	return store
}
