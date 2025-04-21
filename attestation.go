package webauthn

import (
	"encoding/binary"
	"fmt"
	"github.com/MrBoombastic/WebAuthn2Go/aaguid"
	"github.com/google/uuid"
	"log"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// ParsedAuthData holds the structured information from the authenticator data.
type ParsedAuthData struct {
	RPIDHash              []byte
	Flags                 byte
	SignCount             uint32
	AAGUID                uuid.UUID // Present if AT flag is set
	CredentialID          []byte    // Present if AT flag is set
	CredentialPubKeyBytes []byte
	Extensions            map[string]interface{} // Present if ED flag is set
}

// ParseAuthenticatorData returns the parsed data structure or an error
func (w *WebAuthn) ParseAuthenticatorData(authDataBytes []byte) (*ParsedAuthData, error) {
	if len(authDataBytes) < 37 { // Minimum length for rpIdHash, flags, signCount
		return nil, ErrAuthDataTooShort
	}

	parsed := &ParsedAuthData{
		RPIDHash:  authDataBytes[0:32],
		Flags:     authDataBytes[32],
		SignCount: binary.BigEndian.Uint32(authDataBytes[33:37]),
	}

	initialOffset := 37
	currentOffset := initialOffset // Track consumption relative to start of authDataBytes

	// Check if Attested Credential Data is present (AT flag, bit 6)
	if parsed.Flags&0x40 != 0 {
		// Check minimum length for AAGUID and CredID Length
		if len(authDataBytes) < currentOffset+18 {
			return nil, ErrAuthDataTooShortAttested
		}
		formattedAAGUID, err := aaguid.ToUUID(fmt.Sprintf("%x", authDataBytes[currentOffset:currentOffset+16]))
		if err != nil {
			return nil, ErrAAGUIDToUUID
		}

		parsed.AAGUID = formattedAAGUID
		currentOffset += 16

		credIDLenBytes := authDataBytes[currentOffset : currentOffset+2]
		credIDLen := int(binary.BigEndian.Uint16(credIDLenBytes))
		currentOffset += 2

		// Check length for Credential ID
		if len(authDataBytes) < currentOffset+credIDLen {
			return nil, ErrAuthDataTooShortCredentialID
		}
		parsed.CredentialID = authDataBytes[currentOffset : currentOffset+credIDLen]
		currentOffset += credIDLen

		// Credential Public Key (COSE format) follows the credential ID
		credentialKeyBytes := authDataBytes[currentOffset:]
		//var keyBytesRead int // Use int to match NumBytesRead() //we probably don't need this, at least not yet

		if len(credentialKeyBytes) > 0 {
			_, err := webauthncose.ParsePublicKey(credentialKeyBytes)
			if err != nil && parsed.Flags&0x80 == 0 {
				return nil, ErrParsingCOSEKey
			}
			parsed.CredentialPubKeyBytes = credentialKeyBytes
			//currentOffset += keyBytesRead // as above, we are not using it eight now, but may in the future
		} else if parsed.Flags&0x80 == 0 {
			// AT flag set, but no bytes remain for public key, and ED not set.
			return nil, ErrATFlagButNoData
		}
	}

	// Check if Extension data is present (ED flag, bit 7)
	if parsed.Flags&0x80 != 0 {
		if currentOffset >= len(authDataBytes) {
			// ED flag is set, but no data remains after parsing previous parts.
			return nil, ErrEDFlagButNoData
		}
		extensionBytes := authDataBytes[currentOffset:]
		err := webauthncbor.Unmarshal(extensionBytes, &parsed.Extensions)
		if err != nil {
			return nil, ErrFailedDecodeExtensionData
		}
		if w.Config.Debug {
			log.Printf("Parsed extensions: %v\n", parsed.Extensions)
		}
	}

	return parsed, nil
}
