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
	getHashedPassword(userId string) ([]byte, error)
	getVerification(userId string) (Verification, error)
	getReset(userId string) (Reset, error)
	getAppId(userId string) (string, error)

	onSignedUp(evt SignedUpEvent) error
	onVerifiedAccount(evt VerifiedAccountEvent) error
	onRequestedResetPassword(evt RequestedResetPasswordEvent) error
	onConfirmedResetPassword(evt ConfirmedResetPasswordEvent) error
	onChangedEmail(evt ChangedEmailEvent) error
	onChangedPassword(evt ChangedPasswordEvent) error
	onCreatedUser(evt CreatedUserEvent) error
	onUpdatedUserEmail(evt UpdatedUserEmailEvent) error
	onUpdatedUserPassword(evt UpdatedUserPasswordEvent) error
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
		case "RequestedResetPassword":
			evt := RequestedResetPasswordEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onRequestedResetPassword(evt)
		case "ConfirmedResetPassword":
			evt := ConfirmedResetPasswordEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onConfirmedResetPassword(evt)
		case "ChangedEmail":
			evt := ChangedEmailEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onChangedEmail(evt)
		case "ChangedPassword":
			evt := ChangedPasswordEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onChangedPassword(evt)
		case "CreatedUser":
			evt := CreatedUserEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onCreatedUser(evt)
		case "UpdatedUserEmail":
			evt := UpdatedUserEmailEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onUpdatedUserEmail(evt)
		case "UpdatedUserPassword":
			evt := UpdatedUserPasswordEvent{Header: header}
			self.eventStore.MustLoadEvent(header, &evt.Data)
			err = self.onUpdatedUserPassword(evt)
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

func (self *memStore) getHashedPassword(userId string) ([]byte, error) {
	return self.UserById[userId].HashedPassword, nil
}

func (self *memStore) getVerification(userId string) (Verification, error) {
	return self.VerificationByUserId[userId], nil
}

func (self *memStore) getReset(userId string) (Reset, error) {
	return self.ResetByUserId[userId], nil
}

func (self *memStore) getAppId(userId string) (string, error) {
	return self.UserById[userId].AppId, nil
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

func (self *memStore) setVerificationForUser(user User) {
	verification := Verification{UserId: user.Id, Email: user.Email}
	self.setVerification(verification)
}

func (self *memStore) setReset(reset Reset) {
	self.ResetByUserId[reset.UserId] = reset
}

func (self *memStore) delReset(userId string) {
	delete(self.ResetByUserId, userId)
}

func (self *memStore) setHashedPassword(userId string, hashedPassword []byte) {
	user := self.UserById[userId]
	user.HashedPassword = hashedPassword
	self.UserById[userId] = user
}

func (self *memStore) setEmail(userId, email string) {
	user := self.UserById[userId]
	oldEmail := user.Email

	user.Email = email
	self.UserById[userId] = user

	oldKey := getUserIdKey(user.AppId, oldEmail)
	delete(self.UserIdByKey, oldKey)

	newKey := getUserIdKey(user.AppId, email)
	self.UserIdByKey[newKey] = userId
}

func (self *memStore) removeUser(userId string) {
	user := self.UserById[userId]

	delete(self.UserById, userId)
	delete(self.VerificationByUserId, userId)
	delete(self.ResetByUserId, userId)

	key := getUserIdKey(user.AppId, user.Email)
	delete(self.UserIdByKey, key)
}

func getUserIdKey(appId, email string) string {
	return strings.Join([]string{appId, email}, "_")
}
