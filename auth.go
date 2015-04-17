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
	ChangeEmail(sessionToken, newEmail string) error
	ChangePassword(sessionToken, oldPassword, newPassword string) error

	CreateUser(sessionToken, authorizationId, appId, email, password string) error
	ChangeUserPassword(sessionToken, authorizationId, userId, newPassword string) error
	ChangeUserEmail(sessionToken, authorizationId, userId, newEmail string) error
	RemoveUser(sessionToken, authorizationId, userId string) error
	SetAuthorizations(sessionToken, authorizationId string, userIds []string, authorizationIds []string, IsAuthorized bool) error
}

type authServiceImpl struct {
	es event.Store
	ss snapshot.Store
}

func NewAuthService(es event.Store, ss snapshot.Store) AuthService {
	return &authServiceImpl{es: es, ss: ss}
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
			err = sd.OnSignedUp(evt)
		case "VerifiedAccount":
			evt := VerifiedAccountEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnVerifiedAccount(evt)
		case "RequestedResetPassword":
			evt := RequestedResetPasswordEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnRequestedResetPassword(evt)
		case "ConfirmedResetPassword":
			evt := ConfirmedResetPasswordEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnConfirmedResetPassword(evt)
		case "ChangedPassword":
			evt := ChangedPasswordEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnChangedPassword(evt)
		case "ChangedEmail":
			evt := ChangedEmailEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnChangedEmail(evt)
		case "CreatedUser":
			evt := CreatedUserEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnCreatedUser(evt)
		case "ChangedUserPassword":
			evt := ChangedUserPasswordEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnChangedUserPassword(evt)
		case "ChangedUserEmail":
			evt := ChangedUserEmailEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnChangedUserEmail(evt)
		case "RemovedUser":
			evt := RemovedUserEvent{Header: header}
			self.es.MustLoadEventData(header, &evt.Data)
			err = sd.OnRemovedUser(evt)
		}
		// TODO
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
