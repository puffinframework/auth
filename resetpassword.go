package auth

import (
	"time"

	"github.com/puffinframework/event"
	"golang.org/x/crypto/bcrypt"
)

type RequestedResetPasswordEvent struct {
	Header event.Header
	Data   Reset
}

type ConfirmedResetPasswordEvent struct {
	Header event.Header
	Data   ConfirmedResetPasswordEventData
}

type ConfirmedResetPasswordEventData struct {
	UserId         string
	HashedPassword []byte
}

func (self *authServiceImpl) RequestResetPassword(appId, email string) (resetToken string, err error) {
	sd := self.processEvents()

	userId := sd.GetUserId(appId, email)
	if userId == "" {
		return "", ErrResetPasswordDenied
	}

	verification := sd.GetVerification(userId)
	if verification.AppId != appId || verification.Email != email {
		return "", ErrEmailNotVerified
	}

	evt := RequestedResetPasswordEvent{
		Header: event.NewHeader("RequestedResetPassword", 1),
		Data: Reset{
			AppId:     appId,
			Email:     email,
			UserId:    userId,
			CreatedAt: time.Now(),
		},
	}

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return EncodeReset(evt.Data), nil
}

func OnRequestedResetPassword(evt RequestedResetPasswordEvent, sd SnapshotData) error {
	reset := evt.Data
	sd.SetReset(reset)
	return nil
}

func (self *authServiceImpl) ConfirmResetPassword(resetToken string, newPassword string) error {
	sd := self.processEvents()

	reset, err := DecodeReset(resetToken)
	if err != nil {
		return err
	}

	if sd.GetUserId(reset.AppId, reset.Email) != reset.UserId {
		return ErrResetPasswordDenied
	}

	if sd.GetReset(reset.UserId).UserId != reset.UserId {
		return ErrResetPasswordDenied
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return err
	}

	evt := ConfirmedResetPasswordEvent{
		Header: event.NewHeader("ConfirmedResetPassword", 1),
	}
	evt.Data.UserId = reset.UserId
	evt.Data.HashedPassword = hashedPassword

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func OnConfirmedResetPassword(evt ConfirmedResetPasswordEvent, sd SnapshotData) error {
	data := evt.Data
	sd.DelReset(data.UserId)
	sd.SetHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
