package auth

import (
	"github.com/puffinframework/event"
)

type SetAuthorizationsEvent struct {
	Header event.Header
	Data   struct {
		UserIds          []string
		AuthorizationIds []string
		IsAuthorized     bool
	}
}

func (self *authServiceImpl) SetAuthorizations(sessionToken, authorizationId string, userIds []string, authorizationIds []string, isAuthorized bool) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	authorization := sd.GetUserAuthorization(session.UserId, authorizationId)
	if !authorization.IsAuthorized {
		return ErrNotAuthorized
	}

	evt := SetAuthorizationsEvent{
		Header: event.NewHeader("SetAuthorizationsEvent", 1),
	}
	evt.Data.UserIds = userIds
	evt.Data.AuthorizationIds = authorizationIds
	evt.Data.IsAuthorized = isAuthorized

	self.es.MustSaveEventData(evt.Header, evt.Data)
	return nil
}

func (self *snapshotDataImpl) OnSetAuthorizations(evt SetAuthorizationsEvent) error {
	data := evt.Data
	for _, userId := range data.UserIds {
		for _, authorizationId := range data.AuthorizationIds {
			self.setUserAuthorization(userId, authorizationId, data.IsAuthorized)
		}
	}
	return nil
}
