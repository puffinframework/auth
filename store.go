package auth

type Store interface {
	GetUserId(appId, email string) (string, error)
}

type storeImpl struct {
}

func (self *storeImpl) GetUserId(appId, email string) (string, error) {
	return "", nil
}
