package jwt

import (
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
)

var _ = Decoder(rs256Decoder{})

type rs256Decoder struct {
	publicKey *rsa.PublicKey
}

// NewRS256Decoder returns a new decoder based on the given public key.
func NewRS256Decoder(r io.Reader) (Decoder, error) {
	verifySecret, err := ioutil.ReadAll(r)

	if err != nil {
		return nil, err
	}

	key, err := ParseRSAPublicKeyFromPEM(verifySecret)
	if err != nil {
		return nil, err
	}
	return rs256Decoder{
		publicKey: key,
	}, nil
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
func (rs rs256Decoder) Decode(src string, claims Claims) error {
	_, err := ParseWithClaims(
		src,
		claims,
		func(token *Token) (interface{}, error) {
			if _, ok := token.Method.(*SigningMethodRSA); ok {
				return rs.publicKey, nil
			}
			return nil, fmt.Errorf("Unsupported signing method: %v", token.Header["alg"])
		})
	// error in trying to parse the token
	if err != nil {
		return err
	}

	if err := claims.Valid(); err != nil {
		return err
	}

	return nil
}

var _ = Encoder(rs256Encoder{})

type rs256Encoder struct {
	privateKey *rsa.PrivateKey
}

// NewRS256Encoder returns a new decoder based on the given public key.
func NewRS256Encoder(r io.Reader) (Encoder, error) {
	signingSecret, err := ioutil.ReadAll(r)

	if err != nil {
		return nil, err
	}

	key, err := ParseRSAPrivateKeyFromPEM(signingSecret)
	if err != nil {
		return nil, err
	}
	return rs256Encoder{
		privateKey: key,
	}, nil
}

// Encode creates and signs a token based on the provided claims.
//
// Be warned, you are required to supply an expiry, a nonce, and an issuer
// if it is required. This function will not check for those fields.
// As the tokens are immediately dispatched, you may set your own issuing time
// and expiry and not need to worry about any delays causing issues.
func (rs rs256Encoder) Encode(claims Claims) (string, error) {
	token := NewWithClaims(GetSigningMethod("RS256"), claims)

	str, err := token.SignedString(rs.privateKey)
	if err != nil {
		return "", err
	}
	return str, nil
}
