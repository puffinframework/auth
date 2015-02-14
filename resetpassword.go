package auth

import (
	"github.com/puffinframework/event"
)

type RequestedResetPasswordEvent struct {
	Header event.Header
	Data   ResetPasswordRequest
}

func RequestResetPassword(appId, email string, store SnapshotStore) (RequestedResetPasswordEvent, error) {
	/* TODO
	if store.GetUserId(request.AppId, request.Email) != request.UserId {
		return RequestedResetPasswordEvent{}, ErrRequestResetPasswordDenied
	}

	evt := RequestedResetPasswordEvent{
		Header: event.NewHeader("RequestedResetPassword", 1),
		Data:   request,
	}
	return evt, nil
	*/
	return RequestedResetPasswordEvent{}, nil
}

func OnRequestedResetPassword(evt RequestedResetPasswordEvent, store SnapshotStore) error {
	request := evt.Data
	store.SetResetPasswordRequest(request)
	return nil
}
