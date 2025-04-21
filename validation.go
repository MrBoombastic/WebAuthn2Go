package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/MrBoombastic/WebAuthn2Go/utils"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// ValidateLoginData performs the core cryptographic verification of an assertion.
func (w *WebAuthn) ValidateLoginData(c *LoginData) (out ValidationOutput, err error) {
	// Parse and validate ClientData
	var clientData ClientData
	cdb64, err := clientData.ParseWithB64(c.ClientDataJSON)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrFailedUnmarshalClientData, err)
	}

	if clientData.Type != "webauthn.get" {
		return out, fmt.Errorf("%w, got %s", ErrTypeNotWebauthnGet, clientData.Type)
	}

	if allowed, err := w.isAllowedOrigin(clientData.RPOrigin); !allowed {
		return ValidationOutput{}, err
	}

	// Parse and validate AuthenticatorData
	decodedAuthData, err := utils.DecodeBase64URL(c.AuthData)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrFailedDecodeAuthData, err)
	}
	authDataParsed, err := w.ParseAuthenticatorData(decodedAuthData)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrFailedParseClientData, err)
	}

	// Verify AuthenticatorData RP ID Hash
	rpIDHashBytes := sha256.Sum256([]byte(w.Config.RPID))
	if subtle.ConstantTimeCompare(authDataParsed.RPIDHash, rpIDHashBytes[:]) == 0 {
		return out, ErrRPIDHashMismatch
	}

	// Verify User Present flag (UP)
	if authDataParsed.Flags&0x01 == 0 {
		return out, ErrUserPresentFlagNotSet
	}
	// Set User Verified flag based on UV flag (bit 2)
	out.UserVerified = (authDataParsed.Flags & 0x04) != 0

	decodedSignatureData, err := utils.DecodeBase64URL(c.Signature)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrFailedDecodeSignature, err)
	}

	// Verify Signature
	clientDataHashBytes := sha256.Sum256(cdb64) // Use crypto/sha256
	verificationData := append(decodedAuthData, clientDataHashBytes[:]...)

	key, _ := webauthncose.ParsePublicKey(c.PublicKey)
	validSignature, err := webauthncose.VerifySignature(key, verificationData, decodedSignatureData)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrSignatureVerification, err)
	}
	if !validSignature {
		return out, ErrInvalidSignature
	}

	// Verify Sign Count
	if authDataParsed.SignCount <= c.StoredSignCount && (authDataParsed.SignCount != 0 || c.StoredSignCount != 0) { // Allow both being 0, new sign count should be incremented
		return out, fmt.Errorf("%w: received %d, stored %d", ErrSignatureCountMismatch, authDataParsed.SignCount, c.StoredSignCount)
	}
	out.NewSignCount = authDataParsed.SignCount

	return out, nil
}
