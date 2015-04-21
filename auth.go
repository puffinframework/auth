package auth

import "github.com/puffinframework/event"

type Service interface {
	// for users without a session
	SignUp(appId, email, password string) (verificationToken string, err error)
	/*
		OnSignedUp(evt SignedUpEvent) error
		SignIn(appId, email, password string) (sessionToken string, err error)
		VerifyAccount(verificationToken string) error
		OnVerifiedAccount(evt VerifiedAccountEvent) error
		RequestResetPassword(appId, email string) (resetToken string, err error)
		ConfirmResetPassword(resetToken string, newPassword string) error
		// for users within a session
		ChangeEmail(sessionToken, newEmail string) error
		ChangePassword(sessionToken, oldPassword, newPassword string) error
		// for admins
		CreateUser(adminToken, appId, email, password string) error
		OnCreatedUser(evt CreatedUserEvent) error
		UpdateUserPassword(adminToken, userId, newPassword string) error
		UpdateUserEmail(adminToken, userId, newEmail string) error
		RemoveUser(adminToken, userId string) error
	*/
}

type serviceImpl struct {
	eventStore  event.Store
	store       ServiceStore
	adminTokens []AdminToken
}

func NewService(eventStore event.Store, serviceStore ServiceStore, adminTokens []AdminToken) Service {
	return &serviceImpl{eventStore: eventStore, store: serviceStore, adminTokens: adminTokens}
}
