package main

import (
    "time"
    "errors"
    "net/http"
    "gopkg.in/dgrijalva/jwt-go.v3"
)

type Token struct {
    GUID uint
    Type string
    Salt string
    jwt.StandardClaims
}

type TokenPair struct {
    Access string `json:"access"`
    Refresh string `json:"refresh"`
}

var jwtKey = []byte("deadbeef")

func tokenVerify(w http.ResponseWriter, r *http.Request, tokenString string, tokenType string, tokenOut *Token) error {
    token, err := jwt.ParseWithClaims(tokenString, tokenOut, func(token *jwt.Token) (interface{}, error) {
        return jwtKey, nil
    })
    if (err != nil) {
        if (err == jwt.ErrSignatureInvalid) {
            w.WriteHeader(http.StatusUnauthorized)
        } else {
            w.WriteHeader(http.StatusBadRequest)
        }
        return err
    }
    if (tokenOut.Type != tokenType) {
        w.WriteHeader(http.StatusBadRequest)
        return errors.New("Token type mismatch")
    }
    if (!token.Valid) {
        w.WriteHeader(http.StatusUnauthorized)
        return errors.New("Token invalid")
    }
    return nil
}

func newToken(durationMinutes time.Duration, guid uint, tokenType string, salt string) (string, error) {
    expirationTime := time.Now().Add(durationMinutes * time.Minute)

    tokenClaims := Token{
        GUID: guid,
        Type: tokenType,
        Salt: salt,
        StandardClaims: jwt.StandardClaims {
            ExpiresAt: expirationTime.Unix(),
        },
    }

    return jwt.NewWithClaims(jwt.SigningMethodHS512, &tokenClaims).SignedString(jwtKey)
}

func generatePair(salt string, guid uint, pair *TokenPair) error {
    tokenAccessString, err := newToken(5, guid, "access", salt)
    if err != nil {
        return err
    }

    tokenRefreshString, err := newToken(30, guid, "refresh", salt)
    if (err != nil) {
        return err
    }

    pair.Access = tokenAccessString
    pair.Refresh = tokenRefreshString

    return nil
}
