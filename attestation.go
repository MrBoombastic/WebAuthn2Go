package webauthn

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/MrBoombastic/WebAuthn2Go/aaguid"
	"github.com/google/uuid"

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
	Extensions            map[string]any // Present if ED flag is set
}

const minimalDataLen = 37 // Minimal: RPIDHash + flags + sign count = magic number

// ParseAuthenticatorData returns the parsed data structure or an error
func (w *WebAuthn) ParseAuthenticatorData(authDataBytes []byte) (*ParsedAuthData, error) {
	authDataLength := len(authDataBytes)
	if authDataLength < minimalDataLen { // Minimum length for rpIdHash, flags, signCount
		return nil, ErrAuthDataTooShort
	}

	if w.Config.Debug {
		log.Printf("authDataBytes length: %d", authDataLength)
	}

	parsed := &ParsedAuthData{
		RPIDHash:  authDataBytes[0:32],
		Flags:     authDataBytes[32],
		SignCount: binary.BigEndian.Uint32(authDataBytes[33:minimalDataLen]),
	}

	remainingData := authDataLength - minimalDataLen // Attested Credential Data + Extension Data, later only ED if present

	if w.Config.Debug {
		log.Printf("remaining data len: %d", remainingData)
	}

	// Check if Attested Credential Data is present (AT flag, bit 6)
	if parsed.Flags&0x40 != 0 {
		AToffset := minimalDataLen // Track the consumption of Attested Credential Data

		// Check minimum length for AAGUID and CredID Length
		if authDataLength < minimalDataLen+18 {
			return nil, ErrAuthDataTooShortAttested
		}
		formattedAAGUID, err := aaguid.ToUUID(fmt.Sprintf("%x", authDataBytes[AToffset:AToffset+16]))
		if err != nil {
			return nil, ErrAAGUIDToUUID
		}

		parsed.AAGUID = formattedAAGUID
		AToffset += 16 // always

		credIDLenBytes := authDataBytes[AToffset : AToffset+2]
		credIDLen := int(binary.BigEndian.Uint16(credIDLenBytes))
		AToffset += 2 //always

		// Check length for Credential ID
		if authDataLength < AToffset+credIDLen {
			return nil, ErrAuthDataTooShortCredentialID
		}
		parsed.CredentialID = authDataBytes[AToffset : AToffset+credIDLen]
		AToffset += credIDLen

		// Credential Public Key (COSE format) follows the credential ID
		// This Unmarshal-Marshal masturbation from CBOR lib magically (allowExtraData) ignores Extension Data.
		// That way we can calculate the offset and retrieve ED on our own, if present.
		var cborData any
		if err = webauthncbor.Unmarshal(authDataBytes[AToffset:], &cborData); err != nil {
			return nil, err
		}
		credentialKeyBytes, err := webauthncbor.Marshal(cborData)
		if err != nil {
			return nil, err
		}

		// Now we have everything
		remainingData = remainingData - len(credentialKeyBytes) - credIDLen - 16 - 2

		if len(credentialKeyBytes) > 0 {
			_, err := webauthncose.ParsePublicKey(credentialKeyBytes)
			if err != nil && parsed.Flags&0x80 == 0 {
				return nil, ErrParsingCOSEKey
			}
			parsed.CredentialPubKeyBytes = credentialKeyBytes
		} else if parsed.Flags&0x80 == 0 {
			// AT flag set, but no bytes remain for public key, and ED not set.
			return nil, ErrATFlagButNoData
		}
	}

	if w.Config.Debug {
		log.Printf("remaining data: %d", remainingData)
	}

	// Check if Extension data is present (ED flag, bit 7)
	if parsed.Flags&0x80 != 0 {
		if remainingData == 0 {
			// ED flag is set, but no data remains after parsing previous parts.
			return nil, ErrEDFlagButNoData
		}
		extensionBytes := authDataBytes[authDataLength-remainingData:]
		if w.Config.Debug {
			log.Printf("Extension bytes: %v\n", extensionBytes)
		}

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
