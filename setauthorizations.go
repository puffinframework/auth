package auth

func (self *authServiceImpl) SetAuthorizations(sessionToken, authorizationId string, userIds []string, authorizationIds []string, IsAuthorized bool) error {
	sd := self.processEvents()

	session, err := DecodeSession(sessionToken)
	if err != nil {
		return err
	}

	authorization := sd.GetUserAuthorization(session.UserId, authorizationId)
	if !authorization.IsAuthorized {
		return ErrNotAuthorized
	}

	// TODO
	return nil
}

