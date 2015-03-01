package auth

import (
	"time"

	"github.com/puffinframework/event"
	"golang.org/x/crypto/bcrypt"
)

type RequestedResetPasswordEvent struct {
	Header event.Header
	Data   ResetPasswordRequest
}

type ConfirmedResetPasswordEvent struct {
	Header event.Header
	Data   ConfirmedResetPasswordEventData
}

type ConfirmedResetPasswordEventData struct {
	UserId         string
	HashedPassword []byte
}

func RequestResetPassword(appId, email string, store SnapshotStore) (RequestedResetPasswordEvent, error) {
	userId := store.GetUserId(appId, email)
	if userId == "" {
		return RequestedResetPasswordEvent{}, ErrResetPasswordDenied
	}

	verification := store.GetVerification(userId)
	if verification.AppId != appId || verification.Email != email {
		return RequestedResetPasswordEvent{}, ErrEmailNotVerified
	}

	evt := RequestedResetPasswordEvent{
		Header: event.NewHeader("RequestedResetPassword", 1),
		Data: ResetPasswordRequest{
			AppId:     appId,
			Email:     email,
			UserId:    userId,
			CreatedAt: time.Now(),
		},
	}
	return evt, nil
}

func OnRequestedResetPassword(evt RequestedResetPasswordEvent, store SnapshotStore) error {
	request := evt.Data
	store.SetResetPasswordRequest(request)
	return nil
}

func ConfirmResetPassword(request ResetPasswordRequest, newPassword string, store SnapshotStore) (ConfirmedResetPasswordEvent, error) {
	if store.GetUserId(request.AppId, request.Email) != request.UserId {
		return ConfirmedResetPasswordEvent{}, ErrVerificationDenied
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return ConfirmedResetPasswordEvent{}, err
	}

	evt := ConfirmedResetPasswordEvent{
		Header: event.NewHeader("ConfirmedResetPassword", 1),
	}
	evt.Data.UserId = request.UserId
	evt.Data.HashedPassword = hashedPassword
	return evt, nil
}
