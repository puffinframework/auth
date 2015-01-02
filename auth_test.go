package auth_test

import (
	"os"
	"testing"
	//"time"

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

	userId, err := authService.SignUp("app1", "user1@test.com", "123")
	assert.Nil(t, err)
	assert.NotEqual(t, "", userId)

	userId, err = authService.SignUp("app1", "user1@test.com", "qwe")
	assert.Equal(t, auth.ErrEmailAlreadyUsed, err)
	assert.Equal(t, "", userId)

	userId, err = authService.SignUp("app2", "user1@test.com", "asd")
	assert.Nil(t, err)
	assert.NotEqual(t, "", userId)
}

func TestSignIn(t *testing.T) {
	os.Setenv(config.ENV_VAR_NAME, config.MODE_TEST)
	eventStore := event.NewLeveldbStore()
	defer eventStore.MustDestroy()
	snapshotStore := snapshot.NewLeveldbStore()
	defer snapshotStore.MustDestroy()
	authService := auth.NewAuth(eventStore, snapshotStore)

	jwt, err := authService.SignIn("app1", "user1@test.com", "123")
	assert.Equal(t, auth.ErrSignInDenied, err)

	/*userId*/_, err = authService.SignUp("app1", "user1@test.com", "123")
	assert.Nil(t, err)

	jwt, err = authService.SignIn("app1", "user1@test.com", "qwe")
	assert.Equal(t, auth.ErrSignInDenied, err)
	/*
	assert.Equal(t, "", jwt.Id)
	assert.Equal(t, "", jwt.UserId)
	*/
	assert.Equal(t, "", jwt)

	//t0 := time.Now()
	jwt, err = authService.SignIn("app1", "user1@test.com", "123")
	//t1 := time.Now()

	assert.Nil(t, err)
	/*
	assert.NotEqual(t, "", jwt.Id)
	assert.True(t, t0.Before(jwt.CreatedAt))
	assert.True(t, t1.After(jwt.CreatedAt))
	assert.Equal(t, userId, jwt.UserId)
	*/
	assert.NotEqual(t, "", jwt)
}
