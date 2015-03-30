package auth

import (
	"strings"
	"time"

	"github.com/puffinframework/snapshot"
)

type SnapshotData interface {
	GetUserId(appId, email string) string
	GetHashedPassword(userId string) []byte
	GetVerification(userId string) Verification
	GetReset(userId string) Reset
	IsSuperUser(userId string) bool
	GetUserAuthorization(userId, authorizationId string) UserAuthorization

	SetReset(reset Reset)
	DelReset(userId string)

	OnSignedUp(evt SignedUpEvent) error
	OnVerifiedAccount(evt VerifiedAccountEvent) error
	OnChangedPassword(evt ChangedPasswordEvent) error
	OnConfirmedResetPassword(evt ConfirmedResetPasswordEvent) error

	OnCreatedUser(evt CreatedUserEvent) error
	OnChangedUserPassword(evt ChangedUserPasswordEvent) error
}

type snapshotDataImpl struct {
	LastEventDt            time.Time
	SuperUserById          map[string]SuperUser
	UserById               map[string]User
	UserIdByAppIdEmail     map[string]string
	VerificationByUserId   map[string]Verification
	ResetByUserId          map[string]Reset
	UserAuthorizationByKey map[string]UserAuthorization
}

func NewSnapshotData() SnapshotData {
	return &snapshotDataImpl{
		LastEventDt:          time.Unix(0, 0),
		UserById:             make(map[string]User),
		UserIdByAppIdEmail:   make(map[string]string),
		VerificationByUserId: make(map[string]Verification),
	}
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
	key := joinAppIdEmail(appId, email)
	return self.UserIdByAppIdEmail[key]
}

func (self *snapshotDataImpl) GetHashedPassword(userId string) []byte {
	user := self.UserById[userId]
	return user.HashedPassword
}

func (self *snapshotDataImpl) GetVerification(userId string) Verification {
	return self.VerificationByUserId[userId]
}

func joinAppIdEmail(appId, email string) string {
	return strings.Join([]string{appId, email}, "::")
}

func (self *snapshotDataImpl) SetReset(reset Reset) {
	self.ResetByUserId[reset.UserId] = reset
}

func (self *snapshotDataImpl) GetReset(userId string) Reset {
	return self.ResetByUserId[userId]
}

func (self *snapshotDataImpl) DelReset(userId string) {
	delete(self.ResetByUserId, userId)
}

func (self *snapshotDataImpl) IsSuperUser(userId string) bool {
	superUser := self.SuperUserById[userId]
	return superUser.Id != ""
}

func (self *snapshotDataImpl) GetUserAuthorization(userId, authorizationId string) UserAuthorization {
	key := getUserAuthorizationKey(userId, authorizationId)
	return self.UserAuthorizationByKey[key]
}

func getUserAuthorizationKey(userId, authorizationId string) string {
	return strings.Join([]string{userId, authorizationId}, "__")
}

func (self *snapshotDataImpl) createUser(user User) {
	key := joinAppIdEmail(user.AppId, user.Email)
	self.UserIdByAppIdEmail[key] = user.Id
	self.UserById[user.Id] = user
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
