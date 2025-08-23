package incommoncas

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

type SectigoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *SectigoUser) GetEmail() string {
	return u.Email
}

func (u *SectigoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *SectigoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
