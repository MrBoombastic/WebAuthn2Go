package webauthn

import (
	"errors"
	"fmt"
	"github.com/MrBoombastic/WebAuthn2Go/utils"
)

// BeginLogin generates options for the login process using a pre-generated challenge.
// Returns options (with base64url challenge) or an error.
func (w *WebAuthn) BeginLogin(allowedCredentialIDs []string) (*PublicKeyCredentialRequestOptions, error) {
	if w == nil {
		return nil, errors.New("WebAuthn instance is nil")
	}
	challenge, err := utils.GenerateChallenge()
	if err != nil {
		return nil, err
	}

	allowedCredentials := make([]PublicKeyCredentialDescriptor, len(allowedCredentialIDs))
	for i, credID := range allowedCredentialIDs {
		allowedCredentials[i] = PublicKeyCredentialDescriptor{
			Type: "public-key",
			ID:   credID,
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
func (w *WebAuthn) FinishLogin(data *LoginData) (*LoginResult, error) {
	if w == nil {
		return nil, errors.New("WebAuthn instance is nil")
	}
	res, err := w.ValidateLoginData(data)
	if err != nil {
		return nil, fmt.Errorf("assertion validation failed: %w", err)
	}

	return &LoginResult{
		NewSignCount: res.NewSignCount,
		UserVerified: res.UserVerified,
	}, nil
}
