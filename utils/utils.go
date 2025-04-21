package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

var (
	ErrDecodeBase64URL       = fmt.Errorf("failed to decode base64url")
	ErrEmptyDecodedBase64URL = fmt.Errorf("decoded base64url data is empty")
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

// GenerateChallenge creates a random challenge of 32 bytes converted to base64 string in raw url encoding.
// It's used internally, but if you want to use it for your own purposes, let's go.
func GenerateChallenge() (string, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(challenge), nil
}
