package aaguid

import (
	"errors"
	"github.com/google/uuid"
)

const UnknownAuthenticator = "Unknown Authenticator"

var (
	errProvidedNoAAGUID = errors.New("no AAGUID provided")
)

// ToUUID converts string to a UUID.
// It's basically uuid.Parse
func ToUUID(aaguid string) (uuid.UUID, error) {
	if aaguid == "" {
		return uuid.Nil, errProvidedNoAAGUID
	}
	return uuid.Parse(aaguid)
}

// ToUUIDString converts any AAGUID (or UUID) string to a nicely formatted UUID.
// It's basically uuid.Parse returned as string.
func ToUUIDString(aaguid string) (s string, err error) {
	if aaguid == "" {
		return "", errProvidedNoAAGUID
	}
	u, err := uuid.Parse(aaguid)
	if err != nil {
		return "", err
	}

	return u.String(), nil
}

// LookupAuthenticatorUUID returns a human-readable name for a given AAGUID as UUID.
//
// Returns UnknownAuthenticator string if the result is not found.
//
// Example:
//
//	name, err := aaguid.LookupAuthenticatorUUID(uuid.MustParse("2fc0579f-8113-47ea-b116-bb5a8db9202a"))
//	// "YubiKey 5 NFC/5C NFC (CSPN?) FW 5.2, 5.4"
func LookupAuthenticatorUUID(aaguid uuid.UUID) (name string) {
	s, ok := AAGUIDsMap[aaguid.String()]
	if !ok {
		return UnknownAuthenticator
	}
	return s
}
