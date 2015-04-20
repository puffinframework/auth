package auth

import (
	"strings"
	"time"
)

type Store interface {
	GetUserId(appId, email string) (string, error)

	OnSignedUp(evt SignedUpEvent) error
}

type memStore struct {
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByKey          map[string]string
	VerificationByUserId map[string]Verification
	ResetByUserId        map[string]Reset
}

func NewMemStore() Store {
	return &memStore{}
}

func (self *memStore) GetUserId(appId, email string) (string, error) {
	key := getUserIdKey(appId, email)
	return self.UserIdByKey[key], nil
}

func (self *memStore) setLastEventDt(lastEventDt time.Time) error {
	self.LastEventDt = lastEventDt
	return nil
}

func (self *memStore) createUser(user User) error {
	key := getUserIdKey(user.AppId, user.Email)
	self.UserIdByKey[key] = user.Id
	self.UserById[user.Id] = user
	return nil
}

func getUserIdKey(appId, email string) string {
	return strings.Join([]string{appId, email}, "_")
}
