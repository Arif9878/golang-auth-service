package helpers

import (
	"crypto/rsa"

	"github.com/Arif9878/golang-auth-service/assets"
	"github.com/golang-jwt/jwt"
)

func LoadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := assets.GetResources().ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}
