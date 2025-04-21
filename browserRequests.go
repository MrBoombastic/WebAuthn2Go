package webauthn

import (
	"encoding/json"
	"fmt"
	"github.com/MrBoombastic/WebAuthn2Go/utils"
)

type PublicKeyCredential struct {
	ID                string `json:"id"`
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
	clientData        ClientData
}

func (pkc *PublicKeyCredential) Parse(data []byte) (err error) {
	if err := json.Unmarshal(data, pkc); err != nil {
		return fmt.Errorf("%w: %w", ErrFailedUnmarshalPublicKeyCredential, err)
	}
	b, err := utils.DecodeBase64URL(pkc.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedDecodeClientData, err)
	}
	if err := json.Unmarshal(b, &pkc.clientData); err != nil {
		return fmt.Errorf("%w %w", ErrFailedParseClientData, err)
	}
	return nil
}

func (pkc *PublicKeyCredential) ClientData() (c *ClientData) {
	return &pkc.clientData
}

type PublicKeyCredentialAssertion struct {
	// Matches PublicKeyCredential structure from client Assertion
	ID                string `json:"id"`
	Type              string `json:"type"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	clientData        ClientData
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

func (p *PublicKeyCredentialAssertion) Parse(data []byte) (err error) {
	if err := json.Unmarshal(data, p); err != nil {
		return fmt.Errorf("%w: %w", ErrFailedUnmarshalPublicKeyCredentialAssertion, err)
	}
	b, err := utils.DecodeBase64URL(p.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedDecodeClientData, err)
	}
	if err := json.Unmarshal(b, &p.clientData); err != nil {
		return fmt.Errorf("%w: %w", ErrFailedUnmarshalClientData, err)
	}
	return nil
}

func (p *PublicKeyCredentialAssertion) GetChallenge() string {
	return p.clientData.Challenge
}
