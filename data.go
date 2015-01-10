package auth

import (
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
}

type impl struct {
	ss   *snapshot.Store
	data *snapshotData
}

type snapshotData struct {
	LastEventDt          time.Time
	UserById             UserById
	UserIdByEmail        UserIdByEmail
	VerificationByUserId VerificationByUserId
}

func NewSnapshotData(ss snapshot.Store) SnapshotData {
	return nil
}

func Load() {
}

func Save() {
}
