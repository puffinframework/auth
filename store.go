package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/event"
)

type Store interface {
	MustProcessEvents()
	GetUserId(appId, email string) (string, error)
}

type memStore struct {
	eventStore           event.Store
	LastEventDt          time.Time
	UserById             map[string]User
	UserIdByKey          map[string]string
	VerificationByUserId map[string]Verification
	ResetByUserId        map[string]Reset
}

func NewMemStore(eventStore event.Store) Store {
	return &memStore{eventStore: eventStore}
}

func (self *memStore) GetUserId(appId, email string) (string, error) {
	key := getUserIdKey(appId, email)
	return self.UserIdByKey[key], nil
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
