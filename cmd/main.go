package main

import (
	"log"
	"math/rand"
	"time"

	"github.com/Arif9878/golang-auth-service/helpers"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

const (
	kidAttribute = "kid"
	jwkURI       = "http://localhost:8000"
)

type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func main() {

	key := helpers.LoadRSAPrivateKeyFromDisk("private.pem")

	options := keyfunc.Options{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second * 10,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
	}

	jwks, err := keyfunc.Get(jwkURI, options)
	if err != nil {
		log.Fatalf("Failed to get the JWKS from the given URL.\nError:%s", err.Error())
	}

	claims := &jwtCustomClaims{
		"Jon Snow",
		true,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	tokenJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	randomKid := rand.Intn(len(jwks.KIDs()))
	tokenJwt.Header[kidAttribute] = jwks.KIDs()[randomKid]
	signed, err := tokenJwt.SignedString(key)
	if err != nil {
		panic(err)
	}

	// Parse the JWT.
	token, err := jwt.Parse(signed, jwks.Keyfunc)

	if err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err.Error())
	}

	// Check if the token is valid.
	if !token.Valid {
		log.Fatalf("The token is not valid.")
	}
	log.Println("The token is valid.")
	log.Println(token.Claims)
}
