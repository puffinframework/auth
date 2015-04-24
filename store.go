package auth

import (
	"log"
	"strings"
	"time"

	"github.com/puffinframework/event"
)

type Store interface {
	mustProcessEvents()

	getUserId(appId, email string) (string, error)
	getUser(userId string) (User, error)

	onSignedUp(evt SignedUpEvent) error
	onVerifiedAccount(evt VerifiedAccountEvent) error
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

func (self *memStore) mustProcessEvents() {
	if err := self.eventStore.ForEachEventHeader(self.LastEventDt, func(header event.Header) (bool, error) {
		var err error

		switch header.Type {
		case "SignedUp":
			evt := SignedUpEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onSignedUp(evt)
		case "VerifiedAccount":
			evt := VerifiedAccountEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onVerifiedAccount(evt)
		}

		if err != nil {
			self.LastEventDt = header.CreatedAt
		}

		return err == nil, err

	}); err != nil {
		log.Panic(err)
	}
}

func (self *memStore) getUserId(appId, email string) (string, error) {
	key := getUserIdKey(appId, email)
	return self.UserIdByKey[key], nil
}

func (self *memStore) getUser(userId string) (User, error) {
	return self.UserById[userId], nil
}

func (self *memStore) createUser(user User) error {
	key := getUserIdKey(user.AppId, user.Email)
	self.UserIdByKey[key] = user.Id
	self.UserById[user.Id] = user
	return nil
}

func (self *memStore) setVerification(verification Verification) error {
	self.VerificationByUserId[verification.UserId] = verification
	return nil
}

func getUserIdKey(appId, email string) string {
	return strings.Join([]string{appId, email}, "_")
}
