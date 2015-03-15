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

func RequestResetPassword(appId, email string, sn Snapshot) (RequestedResetPasswordEvent, error) {
	userId := sn.GetUserId(appId, email)
	if userId == "" {
		return RequestedResetPasswordEvent{}, ErrResetPasswordDenied
	}

	verification := sn.GetVerification(userId)
	if verification.AppId != appId || verification.Email != email {
		return RequestedResetPasswordEvent{}, ErrEmailNotVerified
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
	return evt, nil
}

func OnRequestedResetPassword(evt RequestedResetPasswordEvent, sn Snapshot) error {
	reset := evt.Data
	sn.SetReset(reset)
	return nil
}

func ConfirmResetPassword(reset Reset, newPassword string, sn Snapshot) (ConfirmedResetPasswordEvent, error) {
	if sn.GetUserId(reset.AppId, reset.Email) != reset.UserId {
		return ConfirmedResetPasswordEvent{}, ErrResetPasswordDenied
	}

	if sn.GetReset(reset.UserId).UserId != reset.UserId {
		return ConfirmedResetPasswordEvent{}, ErrResetPasswordDenied
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return ConfirmedResetPasswordEvent{}, err
	}

	evt := ConfirmedResetPasswordEvent{
		Header: event.NewHeader("ConfirmedResetPassword", 1),
	}
	evt.Data.UserId = reset.UserId
	evt.Data.HashedPassword = hashedPassword
	return evt, nil
}

func OnConfirmedResetPassword(evt ConfirmedResetPasswordEvent, sn Snapshot) error {
	data := evt.Data
	sn.DelReset(data.UserId)
	sn.SetHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
