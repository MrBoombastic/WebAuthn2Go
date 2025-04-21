package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/MrBoombastic/WebAuthn2Go/aaguid"
	"github.com/MrBoombastic/WebAuthn2Go/utils"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// defaultPubKeyCredParams sets up most common algorithms for public key credential parameters.
// Also, they are the only ones supported by this lib.
var defaultPubKeyCredParams = []CredentialParameter{
	{Type: "public-key", Alg: algES256}, // ES256 (P-256)
	{Type: "public-key", Alg: algRS256}, // RS256
}

// BeginRegistration starts the WebAuthn registration process
// It generates a challenge (as bytes) and returns options including
// the challenge encoded as a base64url string.
// Attestation preference is passed as a parameter.
// User verification preference is taken from the WebAuthn configuration.
// FLOW: 1. pass data
func (w *WebAuthn) BeginRegistration(user UserEntity) (navigator *BeginRegistrationOptions, err error) {
	if w == nil {
		return nil, ErrNilInstance
	}
	if w.Config == nil {
		return nil, ErrNilConfig
	}
	// FLOW: 2. generate challenge
	challenge, err := utils.GenerateChallenge()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGeneratingChallenge, err)
	}
	// FLOW 3: return options, done
	return &BeginRegistrationOptions{
		Challenge:        challenge,
		User:             user,
		PubKeyCredParams: defaultPubKeyCredParams,
		Timeout:          w.Config.Timeout,
		Attestation:      w.Config.Attestation,
		UserVerification: w.Config.UserVerification,
		RP:               RelyingPartyEntity{ID: w.Config.RPID, Name: w.Config.RPDisplayName},
	}, nil
}

// FinishRegistration completes the WebAuthn registration process
// FLOW 1: pass data
func (w *WebAuthn) FinishRegistration(data RegistrationData) (*RegistrationResult, error) {
	if w == nil {
		return nil, ErrNilInstance
	}

	// FLOW 2: parse client data
	var clientData ClientData
	if _, err := clientData.ParseWithB64(data.ClientDataJSON); err != nil {
		return nil, ErrFailedParseClientData
	}

	// FLOW 3: validate if challenge exists, origins match, data type is correct
	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("%w, got %s", ErrTypeNotWebauthnCreate, clientData.Type)
	}

	if allowed, err := w.isAllowedOrigin(clientData.RPOrigin); !allowed {
		return nil, err
	}

	// FLOW 4: CBOR decode attestation
	var attObj attestationObject
	decodedAttestationObject, err := base64.RawURLEncoding.DecodeString(data.AttestationObject)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedDecodeAttestationObject, err)
	}
	if err := webauthncbor.Unmarshal(decodedAttestationObject, &attObj); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedDecodeAttestationObject, err)
	}

	// Validate the received attestation format against supported types
	receivedFmt := AttestationPreference(attObj.Fmt) // Cast to enum type
	if !receivedFmt.IsValid() {                      // Use IsValid method on the enum type
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAttestationFormat, receivedFmt)
	}

	// Parse authenticator data (contains AAGUID needed for name lookup)
	authData, err := w.ParseAuthenticatorData(attObj.AuthData)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedParseAuthData, err)
	}

	// Calculate expected RP ID hash
	expectedRPIDHash := sha256.Sum256([]byte(w.Config.RPID))

	// Validate authenticator data flags and RP ID hash
	if subtle.ConstantTimeCompare(authData.RPIDHash, expectedRPIDHash[:]) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrRPIDHashMismatch, err)
	}
	if authData.Flags&0x01 == 0 {
		return nil, ErrUserPresentFlagNotSet
	}

	// Check UV flag (bit 2) in authData.Flags
	if w.Config.UserVerification == UVRequired {
		if authData.Flags&0x04 == 0 {
			return nil, ErrUserVerifiedFlagNotSet
		}
	}

	// Extract public key - must be present
	if authData.CredentialPubKeyBytes == nil {
		return nil, ErrMissingPublicKey
	} // Check if the public key is valid
	if _, err := webauthncose.ParsePublicKey(authData.CredentialPubKeyBytes); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}

	// CredentialID must also be present for registration.
	if authData.CredentialID == nil {
		return nil, ErrMissingCredentialID
	}

	// Convert CredentialID to base64url string for storage/transport
	credIDStr := base64.RawURLEncoding.EncodeToString(authData.CredentialID)
	name := aaguid.LookupAuthenticatorUUID(authData.AAGUID)

	return &RegistrationResult{
		CredentialID:      credIDStr, // Return base64url encoded ID
		PublicKey:         authData.CredentialPubKeyBytes,
		AAGUID:            authData.AAGUID.String(),
		AuthenticatorName: name,               // Use the looked-up name (or default)
		SignCount:         authData.SignCount, // Set the initial sign count from authData
	}, nil
}
