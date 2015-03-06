package auth

import (
	"time"

	"github.com/puffinframework/event"
	"golang.org/x/crypto/bcrypt"
)

type RequestedResetEvent struct {
	Header event.Header
	Data   Reset
}

type ConfirmedResetEvent struct {
	Header event.Header
	Data   ConfirmedResetEventData
}

type ConfirmedResetEventData struct {
	UserId         string
	HashedPassword []byte
}

func RequestResetPassword(appId, email string, store SnapshotStore) (RequestedResetEvent, error) {
	userId := store.GetUserId(appId, email)
	if userId == "" {
		return RequestedResetEvent{}, ErrResetPasswordDenied
	}

	verification := store.GetVerification(userId)
	if verification.AppId != appId || verification.Email != email {
		return RequestedResetEvent{}, ErrEmailNotVerified
	}

	evt := RequestedResetEvent{
		Header: event.NewHeader("RequestedReset", 1),
		Data: Reset{
			AppId:     appId,
			Email:     email,
			UserId:    userId,
			CreatedAt: time.Now(),
		},
	}
	return evt, nil
}

func OnRequestedReset(evt RequestedResetEvent, store SnapshotStore) error {
	reset := evt.Data
	store.SetReset(reset)
	return nil
}

func ConfirmResetPassword(reset Reset, newPassword string, store SnapshotStore) (ConfirmedResetEvent, error) {
	if store.GetUserId(reset.AppId, reset.Email) != reset.UserId {
		return ConfirmedResetEvent{}, ErrResetPasswordDenied
	}

	if store.GetReset(reset.UserId).UserId != reset.UserId {
		return ConfirmedResetEvent{}, ErrResetPasswordDenied
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), 10)
	if err != nil {
		return ConfirmedResetEvent{}, err
	}

	evt := ConfirmedResetEvent{
		Header: event.NewHeader("ConfirmedReset", 1),
	}
	evt.Data.UserId = reset.UserId
	evt.Data.HashedPassword = hashedPassword
	return evt, nil
}

func OnConfirmedReset(evt ConfirmedResetEvent, store SnapshotStore) error {
	data := evt.Data
	store.DelReset(data.UserId)
	store.SetHashedPassword(data.UserId, data.HashedPassword)
	return nil
}
