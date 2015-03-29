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
	//ChangeEmail(sessionToken, userId, newEmail string) error
	ChangePassword(sessionToken, oldPassword, newPassword string) error
	//CreateSuperUser(email, password string) error
	CreateUser(sessionToken, authorizationId, appId, email, password string) error
	ChangeUserPassword(sessionToken, authorizationId, userId, newPassword string) error
	ChangeUserEmail(sessionToken, authorizationId, userId, newEmail string) error
	RemoveUser(sessionToken, authorizationId, userId error) error
	SetAuthorizations(sessionToken, authorizationId string, userIds []string, authorizationIds []string, IsAuthorized bool) error
}

type authServiceImpl struct {
	es event.Store
	ss snapshot.Store
}

func NewAuthService(es event.Store, ss snapshot.Store) AuthService {
	return &authServiceImpl{es: es, ss: ss}
}

func (self *authServiceImpl) CreateUser(sessionToken, authorizationId, appId, email, password string) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	evt, err := CreateUser(session, authorizationId, appId, email, password, sd)
	if err != nil {
		return err
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *authServiceImpl) ChangeUserEmail(sessionToken, authorizationId, userId, newEmail string) error {
	// TODO
	return nil
}

func (self *authServiceImpl) RemoveUser(sessionToken, authorizationId, userId error) error {
	// TODO
	return nil
}

func (self *authServiceImpl) SetAuthorizations(sessionToken, authorizationId string, userIds []string, authorizationIds []string, IsAuthorized bool) error {
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
