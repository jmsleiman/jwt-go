package jwt

// Decoder decodes claims from a string representation of the token.
type Decoder interface {
	Decode(string, Claims) error
}

// Encoder encodes a Claims into a token, signs it, and returns the string.
type Encoder interface {
	Encode(Claims) (string, error)
}
