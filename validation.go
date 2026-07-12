package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// ValidateLoginData performs the core cryptographic verification of an assertion.
// expectedChallenge must be loaded from a trusted, server-side ceremony state.
// commitState must atomically consume that authentication challenge and
// compare-and-swap the stored signature counter.
func (w *WebAuthn) ValidateLoginData(c *LoginData, expectedChallenge string, commitState LoginStateConsumer) (out ValidationOutput, err error) {
	if w == nil {
		return out, ErrNilInstance
	}
	if w.Config == nil {
		return out, ErrNilConfig
	}
	if c == nil {
		return out, ErrNilLoginData
	}

	// Parse and validate ClientData
	var clientData ClientData
	cdb64, err := clientData.ParseWithB64(c.ClientDataJSON)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrFailedUnmarshalClientData, err)
	}

	if clientData.Type != "webauthn.get" {
		return out, fmt.Errorf("%w, got %s", ErrTypeNotWebauthnGet, clientData.Type)
	}
	if err := validateChallenge(expectedChallenge, clientData.Challenge); err != nil {
		return out, err
	}

	if allowed, err := w.isAllowedOrigin(clientData.RPOrigin); !allowed {
		return ValidationOutput{}, err
	}

	if clientData.CrossOrigin {
		return out, ErrCrossOriginNotAllowed
	}
	if err := validateCredentialBinding(c); err != nil {
		return out, err
	}

	// Parse and validate AuthenticatorData
	decodedAuthData, err := decodeBase64URL(c.AuthData, MaxAuthenticatorDataSize, "authenticator data")
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
	if authDataParsed.Flags&0x40 != 0 {
		return out, ErrUnexpectedAttestedCredentialData
	}
	// Set User Verified flag based on UV flag (bit 2)
	out.UserVerified = (authDataParsed.Flags & 0x04) != 0
	if w.Config.UserVerification == UVRequired && !out.UserVerified {
		return out, ErrUserVerifiedFlagNotSet
	}

	decodedSignatureData, err := decodeBase64URL(c.Signature, MaxSignatureSize, "signature")
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrFailedDecodeSignature, err)
	}

	// Verify Signature
	clientDataHashBytes := sha256.Sum256(cdb64) // Use crypto/sha256
	verificationData := make([]byte, 0, len(decodedAuthData)+len(clientDataHashBytes))
	verificationData = append(verificationData, decodedAuthData...)
	verificationData = append(verificationData, clientDataHashBytes[:]...)

	key, err := validateCredentialPublicKey(c.StoredCredential.PublicKey)
	if err != nil {
		return out, err
	}
	validSignature, err := webauthncose.VerifySignature(key, verificationData, decodedSignatureData)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrSignatureVerification, err)
	}
	if !validSignature {
		return out, ErrInvalidSignature
	}

	// Verify Sign Count
	if authDataParsed.SignCount <= c.StoredCredential.SignCount && (authDataParsed.SignCount != 0 || c.StoredCredential.SignCount != 0) { // Allow both being 0, new sign count should be incremented
		return out, fmt.Errorf("%w: received %d, stored %d", ErrSignatureCountMismatch, authDataParsed.SignCount, c.StoredCredential.SignCount)
	}
	out.NewSignCount = authDataParsed.SignCount
	if err := commitLoginState(commitState, expectedChallenge, c.StoredCredential, out.NewSignCount); err != nil {
		return out, err
	}

	return out, nil
}
