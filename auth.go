package auth

type User struct {
	Email      string
	Hash       string
	HashedPass string
}

func SignUp(email string, password string) {
}
