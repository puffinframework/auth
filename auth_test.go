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

func Test(t *testing.T) {
	os.Setenv(config.ENV_VAR_NAME, config.MODE_TEST)

	eventStore := event.NewLeveldbStore()
	snapshotStore := snapshot.NewLeveldbStore()

	authService := auth.NewAuth(eventStore, snapshotStore)
	assert.NotNil(t, authService)
}
