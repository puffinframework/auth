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

	tokenStr, err := authService.SignIn("app1", "user1@test.com", "123")
	assert.Equal(t, auth.ErrSignInDenied, err)

	userId, err := authService.SignUp("app1", "user1@test.com", "123")
	assert.Nil(t, err)

	tokenStr, err = authService.SignIn("app1", "user1@test.com", "qwe")
	assert.Equal(t, auth.ErrSignInDenied, err)
	assert.Equal(t, "", tokenStr)

	tokenStr, err = authService.SignIn("app1", "user1@test.com", "123")
	assert.Nil(t, err)
	assert.NotEqual(t, "", tokenStr)

	authToken, err := auth.ParseJWT(tokenStr)
	assert.Nil(t, err)
	assert.Equal(t, userId, authToken.UserId)

	now := time.Now()
	t0 := now.Add(-1 * time.Minute)
	t1 := now.Add(1 * time.Minute)

	assert.True(t, t0.Before(authToken.CreatedAt))
	assert.True(t, t1.After(authToken.CreatedAt))
}

func TestJWT(t *testing.T) {
	userId := "user-1"
	createdAt := time.Unix(123, 0)

	tokenStr := auth.CreateJWT(auth.AuthToken{UserId: userId, CreatedAt: createdAt})

	authToken, err := auth.ParseJWT(tokenStr)
	assert.Nil(t, err)
	assert.Equal(t, userId, authToken.UserId)
	assert.Equal(t, createdAt, authToken.CreatedAt)
}
