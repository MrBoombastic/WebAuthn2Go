package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
		{"null extension map", true, []byte{0xf6}, ErrFailedDecodeExtensionData},
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

func TestRegistrationCredProtectPolicy(t *testing.T) {
	challenge := testChallenge(3)
	data, _ := validRegistrationData(t, challenge)
	encoded, err := base64.RawURLEncoding.DecodeString(data.AttestationObject)
	if err != nil {
		t.Fatal(err)
	}
	var original attestationObject
	if err := webauthncbor.Unmarshal(encoded, &original); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		minimum    uint8
		extensions map[string]any
		want       error
	}{
		{"older key without policy", 0, nil, nil},
		{"unknown extension", 0, map[string]any{"future-extension": true}, nil},
		{"level 1", 0, map[string]any{"credProtect": 1}, nil},
		{"level 2", 0, map[string]any{"credProtect": 2}, nil},
		{"level 3", 0, map[string]any{"credProtect": 3}, nil},
		{"zero", 0, map[string]any{"credProtect": 0}, ErrInvalidCredProtect},
		{"above range", 0, map[string]any{"credProtect": 4}, ErrInvalidCredProtect},
		{"negative", 0, map[string]any{"credProtect": -1}, ErrInvalidCredProtect},
		{"string", 0, map[string]any{"credProtect": "2"}, ErrInvalidCredProtect},
		{"boolean", 0, map[string]any{"credProtect": true}, ErrInvalidCredProtect},
		{"float", 0, map[string]any{"credProtect": 2.0}, ErrInvalidCredProtect},
		{"null", 0, map[string]any{"credProtect": nil}, ErrInvalidCredProtect},
		{"missing required extension", 2, nil, ErrCredProtectPolicyNotMet},
		{"empty extension map", 2, map[string]any{}, ErrCredProtectPolicyNotMet},
		{"different extension", 2, map[string]any{"hmac-secret": true}, ErrCredProtectPolicyNotMet},
		{"lower level", 2, map[string]any{"credProtect": 1}, ErrCredProtectPolicyNotMet},
		{"requested level", 2, map[string]any{"credProtect": 2}, nil},
		{"higher level", 2, map[string]any{"credProtect": 3}, nil},
		{"required UV level", 3, map[string]any{"credProtect": 2}, ErrCredProtectPolicyNotMet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWebAuthn(t, UVPreferred)
			w.Config.MinCredProtect = tc.minimum
			att := original
			att.AuthData = append([]byte(nil), original.AuthData...)
			if tc.extensions != nil {
				tail, err := webauthncbor.Marshal(tc.extensions)
				if err != nil {
					t.Fatal(err)
				}
				att.AuthData[32] |= 0x80
				att.AuthData = append(att.AuthData, tail...)
			}
			encoded, err := webauthncbor.Marshal(att)
			if err != nil {
				t.Fatal(err)
			}
			input := data
			input.AttestationObject = base64.RawURLEncoding.EncodeToString(encoded)
			committed := false
			_, err = w.FinishRegistration(input, challenge, func(_ string, _ CeremonyType, _ RegistrationResult) error {
				committed = true
				return nil
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			if committed != (tc.want == nil) {
				t.Fatalf("unexpected commit: %v", committed)
			}
		})
	}
}

func TestBeginRegistrationCredProtectOptions(t *testing.T) {
	w := newTestWebAuthn(t, UVPreferred)
	for level, policy := range []string{"", "userVerificationOptional", "userVerificationOptionalWithCredentialIDList", "userVerificationRequired"} {
		config := *w.Config
		config.MinCredProtect = uint8(level)
		configured, err := New(&config)
		if err != nil {
			t.Fatal(err)
		}
		opts, err := configured.BeginRegistration(UserEntity{ID: []byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(opts)
		if err != nil {
			t.Fatal(err)
		}
		if level == 0 {
			if bytes.Contains(encoded, []byte(`"extensions"`)) {
				t.Fatal("default options requested extensions")
			}
		} else if opts.Extensions["credentialProtectionPolicy"] != policy || opts.Extensions["enforceCredentialProtectionPolicy"] != true {
			t.Fatalf("level %d: unexpected extension request: %v", level, opts.Extensions)
		}
	}
	for _, level := range []uint8{4, 255} {
		config := *w.Config
		config.MinCredProtect = level
		if _, err := New(&config); !errors.Is(err, ErrInvalidMinCredProtect) {
			t.Fatalf("level %d: expected invalid policy, got %v", level, err)
		}
	}
}

func TestLoginDoesNotRequireRegistrationCredProtectExtension(t *testing.T) {
	w := newTestWebAuthn(t, UVRequired)
	w.Config.MinCredProtect = 3
	challenge := testChallenge(3)
	data := signedLoginData(t, challenge, 0x05, 1)
	_, err := w.FinishLogin(data, challenge, func(_ string, _ CeremonyType, _ string, _, _ uint32) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
