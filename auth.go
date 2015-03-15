package auth

import (
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
)

type AuthService interface {
	SignUp(appId, email, password string) (verificationToken string, err error)
	SignIn(appId, email, password string) (sessionToken string, err error)
	VerifyAccount(verificationToken string) error
	RequestResetPassword(appId, email string) (resetToken string, err error)
	ConfirmResetPassword(resetToken string, newPassword string) error
	ChangePassword(sessionToken, oldPassword, newPassword string) error
}

type authServiceImpl struct {
	es event.Store
	ss snapshot.Store
}

func NewAuthService(es event.Store, ss snapshot.Store) AuthService {
	return &authServiceImpl{es: es, ss: ss}
}

func (self *authServiceImpl) SignUp(appId, email, password string) (verificationToken string, err error) {
	store := self.processEvents()

	evt, err := SignUp(appId, email, password, store)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeVerification(Verification{AppId: evt.Data.AppId, Email: evt.Data.Email, UserId: evt.Data.Id}), nil
}

func (self *authServiceImpl) VerifyAccount(verificationToken string) error {
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

func (self *authServiceImpl) SignIn(appId, email, password string) (sessionToken string, err error) {
	store := self.processEvents()

	evt, err := SignIn(appId, email, password, store)
	if err != nil {
		return sessionToken, err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeSession(evt.Data), nil
}

func (self *authServiceImpl) RequestResetPassword(appId, email string) (resetToken string, err error) {
	store := self.processEvents()

	evt, err := RequestResetPassword(appId, email, store)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeReset(evt.Data), nil
}

func (self *authServiceImpl) ConfirmResetPassword(resetToken string, newPassword string) error {
	store := self.processEvents()

	reset, err := DecodeReset(resetToken)
	if err != nil {
		return err
	}

	evt, err := ConfirmResetPassword(reset, newPassword, store)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authServiceImpl) ChangePassword(sessionToken, oldPassword, newPassword string) error {
	store := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	evt, err := ChangePassword(session, oldPassword, newPassword, store)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authServiceImpl) processEvents() SnapshotStore {
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
		case "RequestedResetPassword":
			data := Reset{}
			self.es.MustLoadEventData(header, &data)
			evt := RequestedResetPasswordEvent{Header: header, Data: data}
			err = OnRequestedResetPassword(evt, store)
		case "ConfirmedResetPassword":
			data := ConfirmedResetPasswordEventData{}
			self.es.MustLoadEventData(header, &data)
			evt := ConfirmedResetPasswordEvent{Header: header, Data: data}
			err = OnConfirmedResetPassword(evt, store)
		case "ChangedPassword":
			data := ChangedPasswordEventData{}
			self.es.MustLoadEventData(header, &data)
			evt := ChangedPasswordEvent{Header: header, Data: data}
			err = OnChangedPassword(evt, store)
		}
		return err == nil, err
	})

	store.Save()
	return store
}

func ProcessEvents(sn snapshot.Snapshot, es event.Store, callback func(header event.Header) (bool, error)) {
	sn.Load()

	es.ForEachEventHeader(sn.GetLastEventDt(), func(header event.Header) (bool, error) {
		sn.SetLastEventDt(header.CreatedAt)
		return callback(header)
	})

	sn.Save()
}
