package webauthn

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestRegistrationAuthenticatorExtensions(t *testing.T) {
	w := newTestWebAuthn(t, UVPreferred)
	challenge := testChallenge(3)
	data, credentialID := validRegistrationData(t, challenge)
	encoded, err := base64.RawURLEncoding.DecodeString(data.AttestationObject)
	if err != nil {
		t.Fatal(err)
	}
	var original attestationObject
	if err := webauthncbor.Unmarshal(encoded, &original); err != nil {
		t.Fatal(err)
	}
	// A 14-byte extension map after the 77-byte P-256 COSE key.
	extensions, err := webauthncbor.Marshal(map[string]any{"hmac-secret": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(extensions) != 14 {
		t.Fatalf("expected 14 extension bytes, got %d", len(extensions))
	}
	for _, tc := range []struct {
		name string
		ed   bool
		tail []byte
		want error
	}{
		{"without extensions", false, nil, nil},
		{"with extensions", true, extensions, nil},
		{"extensions without ED", false, extensions, ErrInvalidAuthenticatorData},
		{"ED without extensions", true, nil, ErrEDFlagButNoData},
		{"truncated extensions", true, extensions[:len(extensions)-1], ErrFailedDecodeExtensionData},
		{"trailing data", true, append(append([]byte(nil), extensions...), 0), ErrFailedDecodeExtensionData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			att := original
			att.AuthData = append(append([]byte(nil), original.AuthData...), tc.tail...)
			if tc.ed {
				att.AuthData[32] |= 0x80
			}
			encoded, err := webauthncbor.Marshal(att)
			if err != nil {
				t.Fatal(err)
			}
			input := data
			input.AttestationObject = base64.RawURLEncoding.EncodeToString(encoded)
			committed := false
			result, err := w.FinishRegistration(input, challenge, func(_ string, _ CeremonyType, _ RegistrationResult) error {
				committed = true
				return nil
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			if tc.want != nil {
				if committed {
					t.Fatal("invalid registration was committed")
				}
				return
			}
			if !committed || result.CredentialID != credentialID || !bytes.Equal(result.PublicKey, original.AuthData[len(original.AuthData)-77:]) {
				t.Fatal("registration did not preserve credential data")
			}
			if tc.ed && result.Extensions["hmac-secret"] != true {
				t.Fatalf("unexpected extensions: %v", result.Extensions)
			}
		})
	}
}

func TestParseAuthenticatorDataRejectsMissingPublicKey(t *testing.T) {
	w := newTestWebAuthn(t, UVPreferred)
	for _, flags := range []byte{0x41, 0xc1} {
		// AT header and a one-byte credential ID, with no public key.
		authData := make([]byte, minimalDataLen+18+1)
		authData[32] = flags
		authData[minimalDataLen+17] = 1
		authData[len(authData)-1] = 1
		_, err := w.ParseAuthenticatorData(authData)
		if !errors.Is(err, ErrATFlagButNoData) {
			t.Fatalf("flags %#x: expected ErrATFlagButNoData, got %v", flags, err)
		}
	}
}
