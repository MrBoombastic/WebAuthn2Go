package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestValidateLoginDataRejectsChallengeMismatch(t *testing.T) {
	w := newTestWebAuthn(t, UVPreferred)
	expected := testChallenge(1)

	_, err := w.ValidateLoginData(&LoginData{
		ClientDataJSON: testClientData(t, "webauthn.get", testChallenge(2), "https://example.com"),
	}, expected, nil)
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("expected ErrChallengeMismatch, got %v", err)
	}
}

func TestFinishRegistrationRejectsChallengeMismatch(t *testing.T) {
	w := newTestWebAuthn(t, UVPreferred)
	expected := testChallenge(1)

	_, err := w.FinishRegistration(RegistrationData{
		ClientDataJSON: testClientData(t, "webauthn.create", testChallenge(2), "https://example.com"),
	}, expected, nil)
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("expected ErrChallengeMismatch, got %v", err)
	}
}

func TestFinishRegistrationCommitsVerifiedCredentialAtomically(t *testing.T) {
	w := newTestWebAuthn(t, UVPreferred)
	challenge := testChallenge(3)
	data, expectedCredentialID := validRegistrationData(t, challenge)

	if _, err := w.FinishRegistration(data, challenge, nil); !errors.Is(err, ErrRegistrationStateConsumerRequired) {
		t.Fatalf("expected ErrRegistrationStateConsumerRequired, got %v", err)
	}

	committed := false
	result, err := w.FinishRegistration(data, challenge, func(gotChallenge string, ceremony CeremonyType, credential RegistrationResult) error {
		if gotChallenge != challenge || ceremony != CeremonyRegistration || credential.CredentialID != expectedCredentialID || len(credential.PublicKey) == 0 {
			return errors.New("unexpected verified registration state")
		}
		committed = true
		return nil
	})
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if !committed || result.CredentialID != expectedCredentialID {
		t.Fatal("verified credential was not committed")
	}
}

func TestValidateLoginDataEnforcesRequiredUserVerification(t *testing.T) {
	w := newTestWebAuthn(t, UVRequired)
	challenge := testChallenge(1)
	credentialID := testChallenge(9)

	_, err := w.ValidateLoginData(&LoginData{
		ClientDataJSON: testClientData(t, "webauthn.get", challenge, "https://example.com"),
		AuthData:       testAuthenticatorData(0x01), // UP without UV
		CredentialID:   credentialID,
		StoredCredential: StoredCredential{
			ID:         credentialID,
			UserHandle: []byte{1},
		},
	}, challenge, nil)
	if !errors.Is(err, ErrUserVerifiedFlagNotSet) {
		t.Fatalf("expected ErrUserVerifiedFlagNotSet, got %v", err)
	}
}

func TestFinishLoginConsumesChallengeOnlyOnce(t *testing.T) {
	w := newTestWebAuthn(t, UVRequired)
	challenge := testChallenge(1)
	data := signedLoginData(t, challenge, 0x05, 1) // UP + UV

	_, err := w.FinishLogin(data, challenge, nil)
	if !errors.Is(err, ErrLoginStateConsumerRequired) {
		t.Fatalf("expected ErrLoginStateConsumerRequired, got %v", err)
	}

	used := false
	consume := func(gotChallenge string, ceremony CeremonyType, credentialID string, previousSignCount, newSignCount uint32) error {
		if used {
			return errors.New("already used")
		}
		if gotChallenge != challenge || ceremony != CeremonyAuthentication || credentialID != data.StoredCredential.ID || previousSignCount != 0 || newSignCount != 1 {
			return errors.New("unexpected login state")
		}
		used = true
		return nil
	}

	result, err := w.FinishLogin(data, challenge, consume)
	if err != nil {
		t.Fatalf("FinishLogin() error = %v", err)
	}
	if !used || !result.UserVerified || result.NewSignCount != 1 || result.CredentialID != data.StoredCredential.ID || result.UserHandle != data.UserHandle {
		t.Fatalf("unexpected login result: %#v, consumed=%v", result, used)
	}

	_, err = w.FinishLogin(data, challenge, consume)
	if !errors.Is(err, ErrLoginStateCommitFailed) {
		t.Fatalf("expected ErrLoginStateCommitFailed on replay, got %v", err)
	}
}

func TestValidateLoginDataRejectsCredentialAndUserHandleMismatch(t *testing.T) {
	w := newTestWebAuthn(t, UVRequired)
	challenge := testChallenge(1)
	data := signedLoginData(t, challenge, 0x05, 1)
	called := false
	commit := func(string, CeremonyType, string, uint32, uint32) error {
		called = true
		return nil
	}

	originalCredentialID := data.CredentialID
	data.CredentialID = testChallenge(8)
	_, err := w.ValidateLoginData(data, challenge, commit)
	if !errors.Is(err, ErrCredentialIDMismatch) {
		t.Fatalf("expected ErrCredentialIDMismatch, got %v", err)
	}
	if called {
		t.Fatal("login state must not be committed after a credential mismatch")
	}

	data.CredentialID = originalCredentialID
	data.UserHandle = base64.RawURLEncoding.EncodeToString([]byte("another-user"))
	_, err = w.ValidateLoginData(data, challenge, commit)
	if !errors.Is(err, ErrUserHandleMismatch) {
		t.Fatalf("expected ErrUserHandleMismatch, got %v", err)
	}

	data.UserHandle = ""
	data.RequireUserHandle = true
	_, err = w.ValidateLoginData(data, challenge, commit)
	if !errors.Is(err, ErrUserHandleRequired) {
		t.Fatalf("expected ErrUserHandleRequired, got %v", err)
	}
}

func TestNewRejectsUnsafeOrInconsistentOrigins(t *testing.T) {
	tests := []struct {
		name   string
		rpid   string
		origin string
		want   error
	}{
		{name: "http outside localhost", rpid: "example.com", origin: "http://example.com", want: ErrInsecureOrigin},
		{name: "origin path", rpid: "example.com", origin: "https://example.com/path", want: ErrInvalidRPOrigin},
		{name: "origin query", rpid: "example.com", origin: "https://example.com?x=1", want: ErrInvalidRPOrigin},
		{name: "origin user info", rpid: "example.com", origin: "https://attacker@example.com", want: ErrInvalidRPOrigin},
		{name: "unrelated origin", rpid: "example.com", origin: "https://evil.example", want: ErrRPIDOriginMismatch},
		{name: "public suffix RP ID", rpid: "co.uk", origin: "https://login.co.uk", want: ErrInvalidRPID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(&Config{
				RPID:             tt.rpid,
				RPDisplayName:    "Example",
				RPOrigins:        []string{tt.origin},
				Timeout:          60_000,
				UserVerification: UVPreferred,
				Attestation:      AttestationNone,
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, err)
			}
		})
	}
}

func TestOriginNormalizationHandlesDefaultHTTPSPort(t *testing.T) {
	w, err := New(&Config{
		RPID:             "EXAMPLE.COM",
		RPDisplayName:    "Example",
		RPOrigins:        []string{"https://EXAMPLE.COM:443"},
		Timeout:          60_000,
		UserVerification: UVPreferred,
		Attestation:      AttestationNone,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	allowed, err := w.isAllowedOrigin("https://example.com")
	if err != nil || !allowed {
		t.Fatalf("expected normalized origin to be allowed, allowed=%v err=%v", allowed, err)
	}

	allowed, err = w.isAllowedOrigin("https://example.com/path")
	if allowed || !errors.Is(err, ErrParsingOrigin) {
		t.Fatalf("expected path-bearing client origin to be rejected, allowed=%v err=%v", allowed, err)
	}
}

func TestParseWithB64RejectsOversizedClientData(t *testing.T) {
	oversized := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, MaxClientDataJSONSize+1))
	var data ClientData
	_, err := data.ParseWithB64(oversized)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge, got %v", err)
	}
}

func TestAllowedCredentialAlgorithms(t *testing.T) {
	if !isAllowedCredentialAlgorithm(algES256) || !isAllowedCredentialAlgorithm(algRS256) {
		t.Fatal("configured credential algorithms must be allowed")
	}
	if isAllowedCredentialAlgorithm(-65535) { // RS1 / SHA-1
		t.Fatal("RS1 must not be allowed")
	}
}

func TestValidateCredentialPublicKeyRejectsAlgorithmNotOffered(t *testing.T) {
	keyBytes, err := webauthncbor.Marshal(webauthncose.RSAPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.RSAKey),
			Algorithm: int64(webauthncose.AlgRS1),
		},
		Modulus:  []byte{1},
		Exponent: []byte{3},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	_, err = validateCredentialPublicKey(keyBytes)
	if !errors.Is(err, ErrUnsupportedCredentialAlgorithm) {
		t.Fatalf("expected ErrUnsupportedCredentialAlgorithm, got %v", err)
	}
}

func TestValidateCredentialPublicKeyRejectsOKPMasqueradingAsES256(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	keyBytes, err := webauthncbor.Marshal(webauthncose.OKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.OctetKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		XCoord: publicKey,
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	_, err = validateCredentialPublicKey(keyBytes)
	if !errors.Is(err, ErrUnsupportedCredentialAlgorithm) {
		t.Fatalf("expected ErrUnsupportedCredentialAlgorithm, got %v", err)
	}
}

func TestValidateCredentialPublicKeyAcceptsStrongRS256(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	keyBytes, err := webauthncbor.Marshal(webauthncose.RSAPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.RSAKey),
			Algorithm: int64(webauthncose.AlgRS256),
		},
		Modulus:  privateKey.PublicKey.N.Bytes(),
		Exponent: big.NewInt(int64(privateKey.PublicKey.E)).Bytes(),
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if _, err := validateCredentialPublicKey(keyBytes); err != nil {
		t.Fatalf("valid RS256 key rejected: %v", err)
	}
}

func TestCommitRegistrationStateRequiresSuccessfulAtomicConsumer(t *testing.T) {
	challenge := testChallenge(1)
	credential := RegistrationResult{CredentialID: testChallenge(2), PublicKey: []byte("public-key"), SignCount: 7}
	if err := commitRegistrationState(nil, challenge, credential); !errors.Is(err, ErrRegistrationStateConsumerRequired) {
		t.Fatalf("expected ErrRegistrationStateConsumerRequired, got %v", err)
	}

	commitErr := errors.New("transaction failed")
	if err := commitRegistrationState(func(string, CeremonyType, RegistrationResult) error { return commitErr }, challenge, credential); !errors.Is(err, ErrRegistrationStateCommitFailed) {
		t.Fatalf("expected ErrRegistrationStateCommitFailed, got %v", err)
	}

	committed := false
	if err := commitRegistrationState(func(gotChallenge string, ceremony CeremonyType, gotCredential RegistrationResult) error {
		if gotChallenge != challenge || ceremony != CeremonyRegistration || gotCredential.CredentialID != credential.CredentialID || gotCredential.SignCount != credential.SignCount {
			return errors.New("unexpected ceremony state")
		}
		committed = true
		return nil
	}, challenge, credential); err != nil {
		t.Fatalf("commitRegistrationState() error = %v", err)
	}
	if !committed {
		t.Fatal("expected registration state consumer to run")
	}
}

func newTestWebAuthn(t *testing.T, uv UserVerificationRequirement) *WebAuthn {
	t.Helper()
	w, err := New(&Config{
		RPID:             "example.com",
		RPDisplayName:    "Example",
		RPOrigins:        []string{"https://example.com"},
		Timeout:          60_000,
		UserVerification: uv,
		Attestation:      AttestationNone,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return w
}

func testChallenge(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func testClientData(t *testing.T, ceremonyType, challenge, origin string) string {
	t.Helper()
	b, err := json.Marshal(ClientData{
		Type:        ceremonyType,
		Challenge:   challenge,
		RPOrigin:    origin,
		CrossOrigin: false,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func testAuthenticatorData(flags byte) string {
	b := make([]byte, minimalDataLen)
	rpIDHash := sha256.Sum256([]byte("example.com"))
	copy(b, rpIDHash[:])
	b[32] = flags
	return base64.RawURLEncoding.EncodeToString(b)
}

func validRegistrationData(t *testing.T, challenge string) (RegistrationData, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: algES256,
		},
		Curve:  int64(webauthncose.P256),
		XCoord: privateKey.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord: privateKey.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("Marshal(public key) error = %v", err)
	}

	credentialID := bytes.Repeat([]byte{0xa5}, 32)
	rpIDHash := sha256.Sum256([]byte("example.com"))
	authData := append([]byte{}, rpIDHash[:]...)
	authData = append(authData, 0x41, 0, 0, 0, 0) // UP + AT, sign count 0.
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, 0, byte(len(credentialID)))
	authData = append(authData, credentialID...)
	authData = append(authData, publicKey...)

	attestation, err := webauthncbor.Marshal(attestationObject{
		AuthData: authData,
		Fmt:      string(AttestationNone),
		AttStmt:  map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("Marshal(attestation object) error = %v", err)
	}

	return RegistrationData{
		ClientDataJSON:    testClientData(t, "webauthn.create", challenge, "https://example.com"),
		AttestationObject: base64.RawURLEncoding.EncodeToString(attestation),
	}, base64.RawURLEncoding.EncodeToString(credentialID)
}

func signedLoginData(t *testing.T, challenge string, flags byte, signCount byte) *LoginData {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	clientData := testClientData(t, "webauthn.get", challenge, "https://example.com")
	clientDataBytes, err := base64.RawURLEncoding.DecodeString(clientData)
	if err != nil {
		t.Fatalf("DecodeString(clientData) error = %v", err)
	}
	authDataBytes, err := base64.RawURLEncoding.DecodeString(testAuthenticatorData(flags))
	if err != nil {
		t.Fatalf("DecodeString(authData) error = %v", err)
	}
	authDataBytes[len(authDataBytes)-1] = signCount

	clientDataHash := sha256.Sum256(clientDataBytes)
	verificationData := append(append([]byte(nil), authDataBytes...), clientDataHash[:]...)
	digest := sha256.Sum256(verificationData)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	signature, err := asn1.Marshal(testECDSASignature{R: r, S: s})
	if err != nil {
		t.Fatalf("asn1.Marshal() error = %v", err)
	}

	publicKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: privateKey.PublicKey.X.FillBytes(make([]byte, 32)),
		YCoord: privateKey.PublicKey.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("Marshal(public key) error = %v", err)
	}

	return &LoginData{
		ClientDataJSON: clientData,
		AuthData:       base64.RawURLEncoding.EncodeToString(authDataBytes),
		Signature:      base64.RawURLEncoding.EncodeToString(signature),
		CredentialID:   testChallenge(7),
		UserHandle:     base64.RawURLEncoding.EncodeToString([]byte("test-user-handle")),
		StoredCredential: StoredCredential{
			ID:         testChallenge(7),
			PublicKey:  publicKey,
			SignCount:  0,
			UserHandle: []byte("test-user-handle"),
		},
	}
}

type testECDSASignature struct {
	R, S *big.Int
}
