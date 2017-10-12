package jwt_test

import (
	"fmt"
	"reflect"

	"github.com/darkgopher/dark"
	"github.com/dgrijalva/jwt-go"
)

func testRoundTrip(enc jwt.Encoder, dec jwt.Decoder, claims jwt.Claims) error {
	tokenstr, err := enc.Encode(claims)
	if err != nil {
		return fmt.Errorf("can't Encode: %s", err)
	}

	cp := dark.DeepCopy(claims)
	if err := dec.Decode(tokenstr, cp.(jwt.Claims)); err != nil {
		return fmt.Errorf("can't Decode: %s", err)
	}

	if !reflect.DeepEqual(cp, claims) {
		return fmt.Errorf("%v != %v", cp, claims)
	}

	return nil
}
