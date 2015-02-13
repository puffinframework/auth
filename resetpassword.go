package auth

import (
	"github.com/puffinframework/event"
)

type RequestedResetPasswordEvent struct {
	Header event.Header
	Data   ResetPasswordRequest
}

func RequestResetPassword(request ResetPasswordRequest, store SnapshotStore) (RequestedResetPasswordEvent, error) {
	if store.GetUserId(request.AppId, request.Email) != request.UserId {
		return RequestedResetPasswordEvent{}, ErrRequestResetPasswordDenied
	}

	evt := RequestedResetPasswordEvent{
		Header: event.NewHeader("RequestedResetPassword", 1),
		Data:   request,
	}
	return evt, nil
}

func OnRequestedResetPassword(evt RequestedResetPasswordEvent, store SnapshotStore) error {
	request := evt.Data
	store.SetResetPasswordRequest(request)
	return nil
}
