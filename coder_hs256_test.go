package jwt_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestHS256(t *testing.T) {
	tests := []struct {
		claims jwt.Claims
		secret string
	}{
		{
			claims: &struct {
				Foo string `json:"foo"`
				Bar int    `json:"bar"`
				jwt.StandardClaims
			}{
				Foo: "bar",
				Bar: 5,
			},
			secret: "nerfthis",
		},
		{
			claims: &struct {
				Bleh int  `json:"bleh"`
				Ok   bool `json:"ok"`
				jwt.StandardClaims
			}{
				Bleh: 15,
				Ok:   true,
			},
			secret: "ubersecret",
		},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			enc, err := jwt.NewHS256Encoder(strings.NewReader(test.secret))
			if err != nil {
				t.Fatalf("can't create Encoder: %s", err)
			}

			dec, err := jwt.NewHS256Decoder(strings.NewReader(test.secret))
			if err != nil {
				t.Fatalf("can't create Decoder: %s", err)
			}

			if err := testRoundTrip(enc, dec, test.claims); err != nil {
				t.Fatalf("problem with round trip: %s", err)
			}
		})
	}
}
