package jwt

import (
	"fmt"
	"io"
	"io/ioutil"
)

var _ = Decoder(hs256{})
var _ = Encoder(hs256{})

type hs256 struct {
	secret []byte
}

func newhs(r io.Reader) (hs256, error) {
	secret, err := ioutil.ReadAll(r)

	if err != nil {
		return hs256{}, err
	}

	return hs256{
		secret: secret,
	}, nil
}

// NewHS256Decoder returns a jwt decoder based on HS256 encryption.
func NewHS256Decoder(r io.Reader) (Decoder, error) {
	return newhs(r)
}

// Decode takes a token string and a set of claims and tries to populate
// the claims. It will do the following:
// (1) It will check if the signature was valid (is this token forged?)
// (2) It will check if the token is indeed a token
// (3) It will check the validity of the token based on your Claims.Valid()
//
// If embedding the StandardClaims type in your Claims struct:
// (4) It will check for exp, iat, and nbf but will not check jti, iss, aud,
// and others
//
// Otherwise it will only call your Claims.Valid() and you are responsible for
// those checks.
// Remember to pass a &claims :)
func (hs hs256) Decode(src string, claims Claims) error {
	_, err := ParseWithClaims(
		src,
		claims,
		func(token *Token) (interface{}, error) {
			if _, ok := token.Method.(*SigningMethodHMAC); ok {
				return hs.secret, nil
			}
			return nil, fmt.Errorf("Unsupported signing method: %v", token.Header["alg"])
		})

	if err != nil {
		return err
	}
	/*
		if err := claims.Valid(); err != nil {
			return err
		}
	*/

	return nil
}

// NewHS256Encoder returns a jwt encoder based on HS256 encryption.
func NewHS256Encoder(r io.Reader) (Encoder, error) {
	return newhs(r)
}

// Encode creates and signs a token based on the provided claims.
//
// Be warned, you are required to supply an expiry, a nonce, and an issuer
// if it is required. This function will not check for those fields.
// As the tokens are immediately dispatched, you may set your own issuing time
// and expiry and not need to worry about any delays causing issues.
func (hs hs256) Encode(claims Claims) (string, error) {
	token := NewWithClaims(GetSigningMethod("HS256"), claims)

	str, err := token.SignedString(hs.secret)
	if err != nil {
		return "", err
	}
	return str, nil
}
