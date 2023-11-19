package api

import (
	"fmt"
	"log"
	"secure_file_transfer/env"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtSigningKey []byte
var jwtSessionLengthMinutes time.Duration = 15
var jwtSigningMethod = jwt.SigningMethodHS256

type JWTValues map[string]string

// Get gets the first value associated with the given key.
func (v JWTValues) Get(key string) string {
	if v == nil {
		return ""
	}
	vs := v[strings.ToLower(key)]
	if len(vs) == 0 {
		return ""
	}
	return vs
}

// Set sets the key to value. It replaces any existing
// values.
func (v JWTValues) Set(key, value string) {
	v[strings.ToLower(key)] = value
}

type CustomClaims struct {
	Vars JWTValues
	jwt.RegisteredClaims
}

func init() {
	jwtSigningKey = []byte(env.GetAsString("JWT_SIGNING_KEY", "bestestlms"))
}

func CreateJWTTokenForUser(v JWTValues) string {
	claims := CustomClaims{
		v,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * jwtSessionLengthMinutes)),
		},
	}

	// Encode to token string
	tokenString, err := jwt.NewWithClaims(jwtSigningMethod, claims).SignedString(jwtSigningKey)
	if err != nil {
		log.Println("Error occurred generating JWT", err)
		return ""
	}
	return tokenString
}

func DecodeJWTToUser(token string) (JWTValues, error) {
	// Decode
	decodeToken, err := jwt.ParseWithClaims(token, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if !(jwtSigningMethod == token.Method) {
			// Check our method hasn't changed since issuance
			return nil, fmt.Errorf("signing method mismatch")
		}
		return jwtSigningKey, nil
	})

	// GTFO
	if err != nil {
		return JWTValues{}, err
	}

	// There's two parts. We might decode it successfully but it might
	// be the case we aren't Valid so you must check both
	if decClaims, ok := decodeToken.Claims.(*CustomClaims); ok && decodeToken.Valid {
		return decClaims.Vars, nil
	}

	return JWTValues{}, err
}
