package auth

/*
import (
	"time"

	"github.com/puffinframework/event"
)

type RequestedResetPasswordEvent struct {
	Header event.Header
	Data   Reset
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

func (self *snapshotDataImpl) OnRequestedResetPassword(evt RequestedResetPasswordEvent) error {
	reset := evt.Data
	self.setReset(reset)
	return nil
}
*/
