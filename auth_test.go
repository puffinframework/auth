package auth_test

import (
	"os"
	"testing"

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
	authService := auth.NewAuth(eventStore, snapshotStore)

	assert.Nil(t, authService.SignUp("app1", "test@test.com", "123"))
	assert.Equal(t, auth.ErrEmailAlreadyUsed, authService.SignUp("app1", "test@test.com", "qwe"))
	assert.Nil(t, authService.SignUp("app2", "test@test.com", "asd"))
}

func TestSignIn(t *testing.T) {
	os.Setenv(config.ENV_VAR_NAME, config.MODE_TEST)
	eventStore := event.NewLeveldbStore()
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore()
	defer snapshotStore.MustDestroy()
	authService := auth.NewAuth(eventStore, snapshotStore)

	session, err := authService.SignIn("app1", "user1@test.com", "123")
	assert.Equal(t, auth.ErrSignInDenied, err)
	assert.Equal(t, "", session.Id)
}
