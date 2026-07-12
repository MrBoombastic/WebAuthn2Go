package webauthn

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"

	"github.com/MrBoombastic/WebAuthn2Go/utils"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

func decodeBase64URL(input string, maxDecodedLen int, field string) ([]byte, error) {
	decoded, err := utils.DecodeBase64URLWithLimit(input, maxDecodedLen)
	if err != nil {
		if errors.Is(err, utils.ErrDecodedBase64URLTooLarge) {
			return nil, fmt.Errorf("%w: %s", ErrInputTooLarge, field)
		}
		return nil, err
	}
	return decoded, nil
}

func validateChallenge(expected, received string) error {
	if expected == "" {
		return ErrMissingChallenge
	}

	expectedBytes, err := decodeBase64URL(expected, MaxChallengeSize, "expected challenge")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidChallenge, err)
	}
	if len(expectedBytes) < MinChallengeSize || base64.RawURLEncoding.EncodeToString(expectedBytes) != expected {
		return fmt.Errorf("%w: expected challenge", ErrInvalidChallenge)
	}

	receivedBytes, err := decodeBase64URL(received, MaxChallengeSize, "received challenge")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidChallenge, err)
	}
	if len(receivedBytes) < MinChallengeSize || base64.RawURLEncoding.EncodeToString(receivedBytes) != received {
		return fmt.Errorf("%w: received challenge", ErrInvalidChallenge)
	}

	if subtle.ConstantTimeCompare(expectedBytes, receivedBytes) != 1 {
		return ErrChallengeMismatch
	}
	return nil
}

func consumeChallenge(consumer ChallengeConsumer, challenge string, ceremony CeremonyType) error {
	if consumer == nil {
		return ErrChallengeConsumptionRequired
	}
	if err := consumer(challenge, ceremony); err != nil {
		return fmt.Errorf("%w: %w", ErrChallengeConsumptionFailed, err)
	}
	return nil
}

func commitLoginState(consumer LoginStateConsumer, challenge string, credential StoredCredential, newSignCount uint32) error {
	if consumer == nil {
		return ErrLoginStateConsumerRequired
	}
	if err := consumer(challenge, CeremonyAuthentication, credential.ID, credential.SignCount, newSignCount); err != nil {
		return fmt.Errorf("%w: %w", ErrLoginStateCommitFailed, err)
	}
	return nil
}

func validateCredentialBinding(data *LoginData) error {
	stored := data.StoredCredential
	if stored.ID == "" {
		return ErrMissingStoredCredentialID
	}

	storedID, err := decodeBase64URL(stored.ID, MaxCredentialIDSize, "stored credential ID")
	if err != nil {
		return fmt.Errorf("%w: stored credential ID: %w", ErrInvalidCredentialID, err)
	}
	if base64.RawURLEncoding.EncodeToString(storedID) != stored.ID {
		return fmt.Errorf("%w: stored credential ID", ErrInvalidCredentialID)
	}
	receivedID, err := decodeBase64URL(data.CredentialID, MaxCredentialIDSize, "credential ID")
	if err != nil {
		return fmt.Errorf("%w: response credential ID: %w", ErrInvalidCredentialID, err)
	}
	if base64.RawURLEncoding.EncodeToString(receivedID) != data.CredentialID {
		return fmt.Errorf("%w: response credential ID", ErrInvalidCredentialID)
	}
	if subtle.ConstantTimeCompare(storedID, receivedID) != 1 {
		return ErrCredentialIDMismatch
	}

	if len(stored.UserHandle) == 0 {
		return ErrMissingStoredUserHandle
	}
	if len(stored.UserHandle) > MaxUserHandleSize {
		return fmt.Errorf("%w: stored user handle", ErrInvalidUserHandle)
	}
	if data.UserHandle == "" {
		if data.RequireUserHandle {
			return ErrUserHandleRequired
		}
		return nil
	}

	receivedUserHandle, err := decodeBase64URL(data.UserHandle, MaxUserHandleSize, "user handle")
	if err != nil {
		return fmt.Errorf("%w: response user handle: %w", ErrInvalidUserHandle, err)
	}
	if base64.RawURLEncoding.EncodeToString(receivedUserHandle) != data.UserHandle {
		return fmt.Errorf("%w: response user handle", ErrInvalidUserHandle)
	}
	if subtle.ConstantTimeCompare(stored.UserHandle, receivedUserHandle) != 1 {
		return ErrUserHandleMismatch
	}
	return nil
}

func normalizeRPID(rpid string) (string, error) {
	if rpid == "" {
		return "", ErrEmptyRPID
	}
	if rpid != strings.TrimSpace(rpid) {
		return "", fmt.Errorf("%w: surrounding whitespace", ErrInvalidRPID)
	}
	if err := protocol.ValidateRPID(rpid); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidRPID, err)
	}

	if ip := net.ParseIP(rpid); ip != nil {
		return ip.String(), nil
	}
	if strings.EqualFold(rpid, "localhost") {
		return "localhost", nil
	}

	normalized, err := normalizeDomain(rpid)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidRPID, err)
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(normalized); err != nil {
		return "", fmt.Errorf("%w: RP ID must not be a public suffix", ErrInvalidRPID)
	}
	return normalized, nil
}

func normalizeDomain(domain string) (string, error) {
	if domain == "" || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", errors.New("invalid domain")
	}
	normalized, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", err
	}
	normalized = strings.ToLower(normalized)
	if normalized == "" || strings.ContainsAny(normalized, "/:@?#") {
		return "", errors.New("invalid domain")
	}
	return normalized, nil
}

func parseWebAuthnOrigin(raw string) (parsedOriginData, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return parsedOriginData{}, errors.New("origin is empty or contains surrounding whitespace")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return parsedOriginData{}, err
	}
	if u.Scheme == "" || u.Host == "" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return parsedOriginData{}, errors.New("origin must contain only scheme, host, and optional port")
	}

	scheme := strings.ToLower(u.Scheme)
	hostname := u.Hostname()
	if hostname == "" {
		return parsedOriginData{}, errors.New("origin host is empty")
	}
	if ip := net.ParseIP(hostname); ip != nil {
		hostname = ip.String()
	} else {
		hostname, err = normalizeDomain(hostname)
		if err != nil {
			return parsedOriginData{}, err
		}
	}

	if scheme != "https" && !(scheme == "http" && hostname == "localhost") {
		return parsedOriginData{}, ErrInsecureOrigin
	}

	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}

	return parsedOriginData{scheme: scheme, host: host, hostname: hostname}, nil
}

func rpidMatchesOrigin(rpid string, origin parsedOriginData) bool {
	if rpid == origin.hostname {
		return true
	}
	if rpid == "localhost" || net.ParseIP(rpid) != nil {
		return false
	}
	return strings.HasSuffix(origin.hostname, "."+rpid)
}

func isAllowedCredentialAlgorithm(algorithm int64) bool {
	return algorithm == algES256 || algorithm == algRS256
}

func validateCredentialPublicKey(publicKey []byte) (any, error) {
	if len(publicKey) == 0 {
		return nil, ErrMissingPublicKey
	}
	if len(publicKey) > MaxCredentialPublicKeySize {
		return nil, fmt.Errorf("%w: credential public key", ErrInputTooLarge)
	}

	key, err := webauthncose.ParsePublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}

	switch k := key.(type) {
	case webauthncose.EC2PublicKeyData:
		if k.KeyType != int64(webauthncose.EllipticKey) || k.Algorithm != algES256 || k.Curve != int64(webauthncose.P256) {
			return nil, fmt.Errorf("%w: ES256 requires an EC2 P-256 key", ErrUnsupportedCredentialAlgorithm)
		}
	case webauthncose.RSAPublicKeyData:
		if k.KeyType != int64(webauthncose.RSAKey) || k.Algorithm != algRS256 {
			return nil, fmt.Errorf("%w: RS256 requires an RSA key", ErrUnsupportedCredentialAlgorithm)
		}
		if new(big.Int).SetBytes(k.Modulus).BitLen() < 2048 {
			return nil, fmt.Errorf("%w: RSA modulus must be at least 2048 bits", ErrInvalidPublicKey)
		}
		exponent := new(big.Int).SetBytes(k.Exponent)
		if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Bit(0) == 0 {
			return nil, fmt.Errorf("%w: invalid RSA public exponent", ErrInvalidPublicKey)
		}
	case webauthncose.OKPPublicKeyData:
		return nil, fmt.Errorf("%w: OKP keys were not offered", ErrUnsupportedCredentialAlgorithm)
	default:
		return nil, ErrUnsupportedCredentialAlgorithm
	}
	return key, nil
}
