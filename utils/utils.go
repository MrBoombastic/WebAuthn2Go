package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	ErrDecodeBase64URL          = fmt.Errorf("failed to decode base64url")
	ErrEmptyDecodedBase64URL    = fmt.Errorf("decoded base64url data is empty")
	ErrDecodedBase64URLTooLarge = errors.New("decoded base64url data exceeds maximum allowed size")
)

// DecodeBase64URL decodes a Base64URL encoded string to bytes.
func DecodeBase64URL(input string) ([]byte, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeBase64URL, err)
	}
	if len(bytes) == 0 {
		return nil, ErrEmptyDecodedBase64URL
	}
	return bytes, nil
}

// EncodeBase64URL encodes bytes using unpadded base64url.
func EncodeBase64URL(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}

// DecodeBase64URLWithLimit decodes a raw base64url value after bounding both
// the encoded input and decoded allocation size.
func DecodeBase64URLWithLimit(input string, maxDecodedLen int) ([]byte, error) {
	if maxDecodedLen < 1 {
		return nil, ErrDecodedBase64URLTooLarge
	}
	if len(input) > base64.RawURLEncoding.EncodedLen(maxDecodedLen) {
		return nil, ErrDecodedBase64URLTooLarge
	}

	bytes, err := DecodeBase64URL(input)
	if err != nil {
		return nil, err
	}
	if len(bytes) > maxDecodedLen {
		return nil, ErrDecodedBase64URLTooLarge
	}
	return bytes, nil
}

// GenerateChallenge creates a random challenge of 32 bytes converted to base64 string in raw url encoding.
// It's used internally, but if you want to use it for your own purposes, let's go.
func GenerateChallenge() (string, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(challenge), nil
}
