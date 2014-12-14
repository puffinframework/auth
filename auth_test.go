package auth_test

import (
	"os"
	"testing"

	"github.com/puffinframework/config"
	"github.com/stretchr/testify/assert"
)

type authConfig struct {
	EventStore struct {
		LeveldbDir string
	}
	SnapshotStore struct {
		LeveldbDir string
	}
}

func Test(t *testing.T) {
	os.Setenv(config.ENV_VAR_NAME, config.MODE_TEST)

	cfg := &authConfig{}
	config.MustReadConfig(cfg)
	assert.NotNil(t, cfg)
}
