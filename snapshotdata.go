package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
	GetUserId(appId, email string) string
	GetAppId(userId string) string
	GetHashedPassword(userId string) []byte
	GetVerification(userId string) Verification
	GetReset(userId string) Reset
	GetUserAuthorization(userId, authorizationId string) UserAuthorization

	OnSignedUp(evt SignedUpEvent) error
	OnVerifiedAccount(evt VerifiedAccountEvent) error
	OnChangedPassword(evt ChangedPasswordEvent) error
	OnConfirmedResetPassword(evt ConfirmedResetPasswordEvent) error
	OnRequestedResetPassword(evt RequestedResetPasswordEvent) error
	OnChangedEmail(evt ChangedEmailEvent) error

	OnCreatedUser(evt CreatedUserEvent) error
	OnChangedUserPassword(evt ChangedUserPasswordEvent) error
	OnChangedUserEmail(evt ChangedUserEmailEvent) error
	OnRemovedUser(evt RemovedUserEvent) error
	OnSetAuthorizations(evt SetAuthorizationsEvent) error
}

type snapshotDataImpl struct {
	LastEventDt            time.Time
	UserById               map[string]User
	UserIdByKey            map[string]string
	VerificationByUserId   map[string]Verification
	ResetByUserId          map[string]Reset
	UserAuthorizationByKey map[string]UserAuthorization
}

func NewSnapshotData() SnapshotData {
	return &snapshotDataImpl{}
}

func (self *snapshotDataImpl) LoadFrom(ss snapshot.Store) error {
	ss.MustLoadSnapshot("AuthSnapshot", self)
	return nil
}

func (self *snapshotDataImpl) SaveTo(ss snapshot.Store) error {
	ss.MustSaveSnapshot("AuthSnapshot", self)
	return nil
}

func (self *snapshotDataImpl) GetLastEventDt() (time.Time, error) {
	return self.LastEventDt, nil
}

func (self *snapshotDataImpl) SetLastEventDt(lastEventDt time.Time) error {
	self.LastEventDt = lastEventDt
	return nil
}

func (self *snapshotDataImpl) GetUserId(appId, email string) string {
	key := getUserIdKey(appId, email)
	return self.UserIdByKey[key]
}

func (self *snapshotDataImpl) GetAppId(userId string) string {
	user := self.UserById[userId]
	return user.AppId
}

func (self *snapshotDataImpl) GetHashedPassword(userId string) []byte {
	user := self.UserById[userId]
	return user.HashedPassword
}

func (self *snapshotDataImpl) GetVerification(userId string) Verification {
	return self.VerificationByUserId[userId]
}

func getUserIdKey(appId, email string) string {
	return strings.Join([]string{appId, email}, "::")
}

func (self *snapshotDataImpl) GetReset(userId string) Reset {
	return self.ResetByUserId[userId]
}

func (self *snapshotDataImpl) GetUserAuthorization(userId, authorizationId string) UserAuthorization {
	key := getUserAuthorizationKey(userId, authorizationId)
	return self.UserAuthorizationByKey[key]
}

func (self *snapshotDataImpl) setUserAuthorization(userId, authorizationId string, isAuthorized bool) {
	key := getUserAuthorizationKey(userId, authorizationId)
	authorization := self.UserAuthorizationByKey[key]
	authorization.UserId = userId
	authorization.AuthorizationId = authorizationId
	authorization.IsAuthorized = isAuthorized
}

func getUserAuthorizationKey(userId, authorizationId string) string {
	return strings.Join([]string{userId, authorizationId}, "__")
}

func (self *snapshotDataImpl) createUser(user User) {
	key := getUserIdKey(user.AppId, user.Email)
	self.UserIdByKey[key] = user.Id
	self.UserById[user.Id] = user
}

func (self *snapshotDataImpl) removeUser(userId string) {
	user := self.UserById[userId]

	delete(self.UserById, userId)
	delete(self.VerificationByUserId, userId)
	delete(self.ResetByUserId, userId)

	key := getUserIdKey(user.AppId, user.Email)
	delete(self.UserIdByKey, key)

	for key, userAuthorization := range self.UserAuthorizationByKey {
		if userAuthorization.UserId == userId {
			delete(self.UserAuthorizationByKey, key)
		}
	}
}

func (self *snapshotDataImpl) setVerification(verification Verification) {
	self.VerificationByUserId[verification.UserId] = verification
}

func (self *snapshotDataImpl) setVerificationForUser(user User) {
	verification := Verification{AppId: user.AppId, Email: user.Email, UserId: user.Id}
	self.setVerification(verification)
}

func (self *snapshotDataImpl) setHashedPassword(userId string, hashedPassword []byte) {
	user := self.UserById[userId]
	user.HashedPassword = hashedPassword
	self.UserById[userId] = user
}

func (self *snapshotDataImpl) setReset(reset Reset) {
	self.ResetByUserId[reset.UserId] = reset
}

func (self *snapshotDataImpl) delReset(userId string) {
	delete(self.ResetByUserId, userId)
}

func (self *snapshotDataImpl) setEmail(userId, email string) {
	user := self.UserById[userId]
	oldEmail := user.Email

	user.Email = email
	self.UserById[userId] = user

	oldKey := getUserIdKey(user.AppId, oldEmail)
	delete(self.UserIdByKey, oldKey)

	newKey := getUserIdKey(user.AppId, email)
	self.UserIdByKey[newKey] = userId
}
