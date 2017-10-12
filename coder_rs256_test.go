package jwt_test

import (
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestRS256(t *testing.T) {
	pubkey, err := ioutil.ReadFile(filepath.Join("test", "sample_key.pub"))
	if err != nil {
		panic("failed to load test keys: " + err.Error())
	}

	privkey, err := ioutil.ReadFile(filepath.Join("test", "sample_key"))
	if err != nil {
		panic("failed to load test keys: " + err.Error())
	}

	tests := []struct {
		claims  jwt.Claims
		public  string
		private string
	}{
		{
			claims: &struct {
				Bleh int  `json:"bleh"`
				Ok   bool `json:"ok"`
				jwt.StandardClaims
			}{
				Bleh: 17,
				Ok:   true,
			},
			public:  string(pubkey),
			private: string(privkey),
		},
	}

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			enc, err := jwt.NewRS256Encoder(strings.NewReader(test.private))
			if err != nil {
				t.Fatalf("can't create Encoder: %s", err)
			}

			dec, err := jwt.NewRS256Decoder(strings.NewReader(test.public))
			if err != nil {
				t.Fatalf("can't create Decoder: %s", err)
			}

			if err := testRoundTrip(enc, dec, test.claims); err != nil {
				t.Fatalf("problem with round trip: %s", err)
			}
		})
	}
}

func TestRS256Decode(t *testing.T) {
	/*const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJiYXIiOjUxfQ.Su9MtdMfPu2j63DQBf8pIHh5wYvlusTWVa8p6SDyPBF_9uohStL4zEaQrnB3WYErxxtPU2TcIN-RM0jsSPVtxqRV-DmWHQhnIYfJIbYPPOap9daKkEbuF6d8gNm1yQ7JXfJWQuvXLPhQYM1FRCuN9T502weoxnFuslRmQfaOBtw"
		const publicKey = `-----BEGIN PUBLIC KEY-----
	MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGtlTACVaYI45ObXI5XK2x905VqT
	ubBFGkL/5qmKUTNU8Kltxr6I2Hxhz0Wscy3HRpYK5RGH8BltI7zjOLeGlCZ5vhG9
	Y2gIYJuyvLgEIt+nTSfDaZJRec0O76m1VitxrMkLPaWGDSdimWKu7oe2VwI7ziwU
	zt4HHQJWjfZKjrIDAgMBAAE=
	-----END PUBLIC KEY-----`
		d, err := NewRS256Decoder([]byte(publicKey))
		if err != nil {
			t.Fatal(err)
		}
		type claims struct {
			Foo string `json:"foo"`
			Bar int    `json:"bar"`
			StandardClaims
		}
		var c claims
		d.Decode(strings.NewReader(token), &c)

		expect := claims{
			Foo: "bar",
			Bar: 51,
		}

		if c != expect {
			t.Fatalf("c != expect, %v != %v", c, expect)
		}*/
}
