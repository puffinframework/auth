package auth

/*
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
}

type snapshotDataImpl struct {
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

func (self *snapshotDataImpl) setReset(reset Reset) {
	self.ResetByUserId[reset.UserId] = reset
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
*/
