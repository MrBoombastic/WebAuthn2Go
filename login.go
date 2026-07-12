package webauthn

import (
	"fmt"

	"github.com/MrBoombastic/WebAuthn2Go/utils"
)

// BeginLogin generates options for the login process using a pre-generated challenge.
// Returns options (with base64url challenge) or an error.
func (w *WebAuthn) BeginLogin(allowedCredentialIDs []string) (*PublicKeyCredentialRequestOptions, error) {
	if w == nil {
		return nil, ErrNilInstance
	}
	if w.Config == nil {
		return nil, ErrNilConfig
	}
	challenge, err := utils.GenerateChallenge()
	if err != nil {
		return nil, err
	}

	var allowedCredentials []PublicKeyCredentialDescriptor
	if len(allowedCredentialIDs) > 0 {
		allowedCredentials = make([]PublicKeyCredentialDescriptor, len(allowedCredentialIDs))
		for i, credID := range allowedCredentialIDs {
			allowedCredentials[i] = PublicKeyCredentialDescriptor{
				Type: "public-key",
				ID:   credID,
			}
		}
	}

	options := &PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		Timeout:          w.Config.Timeout,
		RPID:             w.Config.RPID,
		AllowCredentials: allowedCredentials,
		UserVerification: w.Config.UserVerification,
	}

	return options, nil
}

// FinishLogin completes the WebAuthn login process.
// expectedChallenge must be loaded from a trusted, server-side ceremony state.
// commitState must atomically consume that authentication challenge and
// compare-and-swap the stored signature counter.
func (w *WebAuthn) FinishLogin(data *LoginData, expectedChallenge string, commitState LoginStateConsumer) (*LoginResult, error) {
	if w == nil {
		return nil, ErrNilInstance
	}
	if w.Config == nil {
		return nil, ErrNilConfig
	}
	if data == nil {
		return nil, ErrNilLoginData
	}
	res, err := w.ValidateLoginData(data, expectedChallenge, commitState)
	if err != nil {
		return nil, fmt.Errorf("assertion validation failed: %w", err)
	}

	return &LoginResult{
		NewSignCount: res.NewSignCount,
		UserVerified: res.UserVerified,
		CredentialID: data.StoredCredential.ID,
		UserHandle:   utils.EncodeBase64URL(data.StoredCredential.UserHandle),
	}, nil
}
