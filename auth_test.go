package auth_test

import (
	"os"
	"testing"
	"time"

	"github.com/puffinframework/auth"
	"github.com/puffinframework/config"
	"github.com/puffinframework/event"
	"github.com/puffinframework/snapshot"
	"github.com/stretchr/testify/assert"
)

func TestSignUp(t *testing.T) {
	os.Setenv(config.ENV_VAR_NAME, config.MODE_TEST)
	eventStore := event.NewLeveldbStore()
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore()
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
	os.Setenv(config.ENV_VAR_NAME, config.MODE_TEST)
	eventStore := event.NewLeveldbStore()
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore()
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
	os.Setenv(config.ENV_VAR_NAME, config.MODE_TEST)
	eventStore := event.NewLeveldbStore()
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore()
	defer snapshotStore.MustDestroy()
	authService := auth.NewAuthService(eventStore, snapshotStore)

	// sign up
	verificationToken, err := authService.SignUp("app1", "puffin1@mailinator.com", "123")
	assert.Nil(t, err)

	// try to reset password before verify the account
	authService.RequestResetPassword("app1", "puffin1@mailinagor.com")
	assert.NotNil(t, err)

	// verify account
	err = authService.VerifyAccount(verificationToken)
	assert.Nil(t, err)

	// reset password
	authService.RequestResetPassword("app1", "puffin1@mailinagor.com")
	assert.Nil(t, err)
	// TODO
}
