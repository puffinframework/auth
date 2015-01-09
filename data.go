package auth

import (
	"time"
)

type snapshotData struct {
	LastEventDt          time.Time
	UserById             UserById
	UserIdByEmail        UserIdByEmail
	VerificationByUserId VerificationByUserId
}
