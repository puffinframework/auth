package auth_test

/*
import (
	"testing"
	"time"

	"github.com/puffinframework/auth"
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"

	"github.com/stretchr/testify/assert"
)

func TestSignUp(t *testing.T) {
	eventStore := event.NewLeveldbStore("test-event-store")
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore("test-snapshot-store")
	defer snapshotStore.MustDestroy()
	authService := auth.NewAuthService(eventStore, snapshotStore)

	verificationToken, err := authService.SignUp("app1", "puffin1@mailinator.com", "123")
	assert.Nil(t, err)
	assert.NotEqual(t, "", verificationToken)

	verificationToken, err = authService.SignUp("app1", "puffin1@mailinator.com", "qwe")
	assert.Equal(t, auth.ErrEmailAlreadyUsed, err)
	assert.Equal(t, "", verificationToken)

	verificationToken, err = authService.SignUp("app2", "puffin1@mailinator.com", "asd")
	assert.Nil(t, err)
	assert.NotEqual(t, "", verificationToken)
}

func TestSignIn(t *testing.T) {
	eventStore := event.NewLeveldbStore("test-event-store")
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore("test-snapshot-store")
	defer snapshotStore.MustDestroy()
	authService := auth.NewAuthService(eventStore, snapshotStore)

	// try to sign in without having signed up
	sessionToken, err := authService.SignIn("app1", "puffin1@mailinator.com", "123")
	assert.Equal(t, auth.ErrSignInDenied, err)
	assert.Equal(t, "", sessionToken)

	// sign up
	verificationToken, err := authService.SignUp("app1", "puffin1@mailinator.com", "123")
	assert.Nil(t, err)
	verification, err := auth.DecodeVerification(verificationToken)
	assert.Nil(t, err)

	// try to sign in without having verified the email
	sessionToken, err = authService.SignIn("app1", "puffin1@mailinator.com", "123")
	assert.Equal(t, auth.ErrEmailNotVerified, err)
	assert.Equal(t, "", sessionToken)

	// verify account with the wrong user
	wrongVerification := auth.Verification{AppId: "app2", Email: verification.Email, UserId: verification.UserId}
	wrongVerificationToken := auth.EncodeVerification(wrongVerification)
	err = authService.VerifyAccount(wrongVerificationToken)
	assert.Equal(t, auth.ErrVerificationDenied, err)

	// verify account
	err = authService.VerifyAccount(verificationToken)
	assert.Nil(t, err)

	// try to sign in with the wrong password
	sessionToken, err = authService.SignIn("app1", "puffin1@mailinator.com", "qwe")
	assert.Equal(t, auth.ErrSignInDenied, err)
	assert.Equal(t, "", sessionToken)

	// sign in
	sessionToken, err = authService.SignIn("app1", "puffin1@mailinator.com", "123")
	assert.Nil(t, err)
	assert.NotEqual(t, "", sessionToken)

	session, err := auth.DecodeSession(sessionToken)
	assert.Nil(t, err)
	assert.Equal(t, verification.UserId, session.UserId)

	now := time.Now()
	t0 := now.Add(-1 * time.Minute)
	t1 := now.Add(1 * time.Minute)

	assert.True(t, t0.Before(session.CreatedAt))
	assert.True(t, t1.After(session.CreatedAt))
}

func TestResetPassword(t *testing.T) {
	eventStore := event.NewLeveldbStore("test-event-store")
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore("test-snapshot-store")
	defer snapshotStore.MustDestroy()
	authService := auth.NewAuthService(eventStore, snapshotStore)

	// try to reset password before sign up
	resetToken, err := authService.RequestResetPassword("app1", "puffin1@mailinator.com")
	assert.Equal(t, auth.ErrResetPasswordDenied, err)
	assert.Equal(t, "", resetToken)

	// sign up
	verificationToken, err := authService.SignUp("app1", "puffin1@mailinator.com", "initialPassword")
	assert.Nil(t, err)

	// try to reset password before verify account
	resetToken, err = authService.RequestResetPassword("app1", "puffin1@mailinator.com")
	assert.Equal(t, auth.ErrEmailNotVerified, err)
	assert.Equal(t, "", resetToken)

	// verify account
	err = authService.VerifyAccount(verificationToken)
	assert.Nil(t, err)

	// sign in with initialPassword
	_, err = authService.SignIn("app1", "puffin1@mailinator.com", "initialPassword")
	assert.Nil(t, err)

	// try to confirm reset password without having requested first
	verification, err := auth.DecodeVerification(verificationToken)
	assert.Nil(t, err)
	resetToken = auth.EncodeReset(auth.Reset{
		AppId:     verification.AppId,
		Email:     verification.Email,
		UserId:    verification.UserId,
		CreatedAt: time.Unix(123, 0),
	})
	err = authService.ConfirmResetPassword(resetToken, "newPassword")
	assert.Equal(t, auth.ErrResetPasswordDenied, err)

	// reset password
	resetToken, err = authService.RequestResetPassword("app1", "puffin1@mailinator.com")
	assert.Nil(t, err)
	reset, err := auth.DecodeReset(resetToken)
	assert.Nil(t, err)
	assert.Equal(t, "app1", reset.AppId)
	assert.Equal(t, "puffin1@mailinator.com", reset.Email)
	assert.Equal(t, verification.UserId, reset.UserId)

	// try to confirm reset password with an invalid token
	invalidResetToken := auth.EncodeReset(auth.Reset{
		AppId:     "app1",
		Email:     "puffin1@mailinator.com",
		UserId:    "invalid-user-id",
		CreatedAt: time.Unix(123, 0),
	})
	err = authService.ConfirmResetPassword(invalidResetToken, "newPassword")
	assert.Equal(t, auth.ErrResetPasswordDenied, err)

	// confirm reset password
	err = authService.ConfirmResetPassword(resetToken, "newPassword")
	assert.Nil(t, err)

	// sign in with initialPassword
	_, err = authService.SignIn("app1", "puffin1@mailinator.com", "initialPassword")
	assert.Equal(t, auth.ErrSignInDenied, err)

	// sign in with newPassword
	_, err = authService.SignIn("app1", "puffin1@mailinator.com", "newPassword")
	assert.Nil(t, err)
}

func TestChangePassword(t *testing.T) {
	eventStore := event.NewLeveldbStore("test-event-store")
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore("test-snapshot-store")
	defer snapshotStore.MustDestroy()
	authService := auth.NewAuthService(eventStore, snapshotStore)

	// sign up
	verificationToken, err := authService.SignUp("app1", "puffin1@mailinator.com", "initialPassword")
	assert.Nil(t, err)

	// verify account
	err = authService.VerifyAccount(verificationToken)
	assert.Nil(t, err)

	// sign in
	sessionToken, err := authService.SignIn("app1", "puffin1@mailinator.com", "initialPassword")
	assert.Nil(t, err)

	// try to change password using an invalid sessionToken
	invalidSessionToken := auth.EncodeSession(auth.Session{
		UserId:    "invalid-user-id",
		CreatedAt: time.Unix(123, 0),
	})
	err = authService.ChangePassword(invalidSessionToken, "initialPassword", "newPassword")
	assert.Equal(t, auth.ErrChangePasswordDenied, err)

	// try to change password using a wrong oldPassword
	err = authService.ChangePassword(sessionToken, "123", "newPassword")
	assert.Equal(t, auth.ErrChangePasswordDenied, err)

	// change password
	err = authService.ChangePassword(sessionToken, "initialPassword", "newPassword")
	assert.Nil(t, err)

	// sign in with wrong password
	_, err = authService.SignIn("app1", "puffin1@mailinator.com", "initialPassword")
	assert.Equal(t, auth.ErrSignInDenied, err)
}
*/
