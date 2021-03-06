package main

import (
	"encoding/json"
	"errors"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/Arif9878/golang-auth-service/helpers"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	kidAttribute = "kid"
	jwkURI       = "http://localhost:8000"
)

type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwtv4.StandardClaims
}

func getJWK() (*keyfunc.JWKs, error) {
	refreshInterval := time.Hour
	refreshTimeOut := time.Second * 10
	options := keyfunc.Options{
		RefreshInterval: &refreshInterval,
		RefreshTimeout:  &refreshTimeOut,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
	}

	jwks, err := keyfunc.Get(jwkURI, options)
	if err != nil {
		return nil, err
	}

	return jwks, nil
}

func KIDs(j *keyfunc.JWKs) (kids []string) {
	kids = make([]string, len(j.Keys))
	index := 0
	for kid := range j.Keys {
		kids[index] = kid
		index++
	}
	return kids
}

func validateToken(token *jwt.Token) (interface{}, error) {
	jwks, err := getJWK()
	if err != nil {
		return nil, err
	}

	t, err := new(jwtv4.Parser).Parse(token.Raw, jwks.KeyFunc)
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("The token is not valid.")
	}
	return jwks.KeyFunc(t)
}

func login(c echo.Context) error {

	username := c.FormValue("username")
	password := c.FormValue("password")

	// Throws unauthorized error
	if username != "jon" || password != "shhh!" {
		return echo.ErrUnauthorized
	}

	claims := &jwtCustomClaims{
		"Jon Snow",
		true,
		jwtv4.StandardClaims{
			Issuer:    "jon",
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	tokenJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	key := helpers.LoadRSAPrivateKeyFromDisk("private.pem")

	jwks, err := getJWK()
	if err != nil {
		panic(err)
	}

	kid := KIDs(jwks)

	randomKid := rand.Intn(len(kid))
	tokenJwt.Header[kidAttribute] = kid[randomKid]
	signed, err := tokenJwt.SignedString(key)
	if err != nil {
		panic(err)
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": signed,
	})
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token).Claims
	jsonString, _ := json.Marshal(user)

	// convert json to struct
	data := jwtCustomClaims{}
	json.Unmarshal(jsonString, &data)
	name := data.Name
	return c.String(http.StatusOK, "Welcome "+name+"!")
}

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Login route
	e.POST("/login", login)

	// Unauthenticated route
	e.GET("/", accessible)

	// Configure middleware with the custom claims type
	r := e.Group("/restricted")
	{
		config := middleware.JWTConfig{
			KeyFunc: validateToken,
		}
		r.Use(middleware.JWTWithConfig(config))
		r.GET("", restricted)
	}

	e.Logger.Fatal(e.Start(":1323"))
}
