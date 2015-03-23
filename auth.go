package auth

import (
	"log"

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
	//CreateSuperUser(email, password string) error
	SetAuthorizations(sessionToken string, userIds []string, authorizationIds []string, IsAuthorized bool) error
	CreateUser(sessionToken, appId, email, password string) error
	ChangeUserPassword(sessionToken, userId, newPassword string) error
	ChangeUserEmail(sessionToken, userId, newEmail string) error
	RemoveUser(sessionToken, userId error) error
}

type authServiceImpl struct {
	es event.Store
	ss snapshot.Store
}

func NewAuthService(es event.Store, ss snapshot.Store) AuthService {
	return &authServiceImpl{es: es, ss: ss}
}

func (self *authServiceImpl) SignUp(appId, email, password string) (verificationToken string, err error) {
	sd := self.processEvents()

	evt, err := SignUp(appId, email, password, sd)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeVerification(Verification{AppId: evt.Data.AppId, Email: evt.Data.Email, UserId: evt.Data.Id}), nil
}

func (self *authServiceImpl) VerifyAccount(verificationToken string) error {
	sd := self.processEvents()

	verification, err := DecodeVerification(verificationToken)
	if err != nil {
		return err
	}

	evt, err := VerifyAccount(verification, sd)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authServiceImpl) SignIn(appId, email, password string) (sessionToken string, err error) {
	sd := self.processEvents()

	evt, err := SignIn(appId, email, password, sd)
	if err != nil {
		return sessionToken, err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeSession(evt.Data), nil
}

func (self *authServiceImpl) RequestResetPassword(appId, email string) (resetToken string, err error) {
	sd := self.processEvents()

	evt, err := RequestResetPassword(appId, email, sd)
	if err != nil {
		return
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeReset(evt.Data), nil
}

func (self *authServiceImpl) ConfirmResetPassword(resetToken string, newPassword string) error {
	sd := self.processEvents()

	reset, err := DecodeReset(resetToken)
	if err != nil {
		return err
	}

	evt, err := ConfirmResetPassword(reset, newPassword, sd)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authServiceImpl) ChangePassword(sessionToken, oldPassword, newPassword string) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	evt, err := ChangePassword(session, oldPassword, newPassword, sd)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authServiceImpl) SetAuthorizations(sessionToken string, userIds []string, authorizationIds []string, IsAuthorized bool) error {
	// TODO
	return nil
}

func (self *authServiceImpl) CreateUser(sessionToken, appId, email, password string) error {
	// TODO
	return nil
}

func (self *authServiceImpl) ChangeUserPassword(sessionToken, userId, newPassword string) error {
	// TODO
	return nil
}

func (self *authServiceImpl) ChangeUserEmail(sessionToken, userId, newEmail string) error {
	// TODO
	return nil
}

func (self *authServiceImpl) RemoveUser(sessionToken, userId error) error {
	// TODO
	return nil
}

func (self *authServiceImpl) processEvents() SnapshotData {
	sd := NewSnapshotData()

	if err := sd.(snapshot.Data).LoadFrom(self.ss); err != nil {
		log.Panic(err)
	}

	lastEventDt, err := sd.(snapshot.Data).GetLastEventDt()
	if err != nil {
		log.Panic(err)
	}

	err = self.es.ForEachEventHeader(lastEventDt, func(header event.Header) (bool, error) {
		sd.(snapshot.Data).SetLastEventDt(header.CreatedAt)
		var err error
		switch header.Type {
		case "SignedUp":
			evt := SignedUpEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = OnSignedUp(evt, sd)
		case "VerifiedAccount":
			evt := VerifiedAccountEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = OnVerifiedAccount(evt, sd)
		case "RequestedResetPassword":
			evt := RequestedResetPasswordEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = OnRequestedResetPassword(evt, sd)
		case "ConfirmedResetPassword":
			evt := ConfirmedResetPasswordEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = OnConfirmedResetPassword(evt, sd)
		case "ChangedPassword":
			evt := ChangedPasswordEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = OnChangedPassword(evt, sd)
		}
		return err == nil, err
	})
	if err != nil {
		log.Panic(err)
	}

	if err = sd.(snapshot.Data).SaveTo(self.ss); err != nil {
		log.Panic(err)
	}

	return sd
}
