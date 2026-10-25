package webauthn

import (
	"encoding/json"
	"fmt"
	"log"
)

// New creates a new WebAuthn instance with the provided configuration.
// It preparses and validates the RPOrigins.
func New(config *Config) (*WebAuthn, error) {
	if config == nil {
		return nil, ErrNilConfig
	}

	if !config.Attestation.IsValid() {
		return nil, fmt.Errorf("%w: %v", ErrAttestationNotSupported, config.Attestation)
	}

	if !config.UserVerification.IsValid() {
		return nil, fmt.Errorf("%w: %v", ErrInvalidUserVerification, config.UserVerification)
	}
	if config.MinCredProtect > 3 {
		return nil, ErrInvalidMinCredProtect
	}

	if len(config.RPOrigins) == 0 && len(config.RPRelatedOrigins) == 0 {
		return nil, ErrInvalidRPOrigins
	}

	if config.RPID == "" {
		return nil, ErrEmptyRPID
	}
	normalizedRPID, err := normalizeRPID(config.RPID)
	if err != nil {
		return nil, err
	}
	if config.RPDisplayName == "" {
		return nil, ErrEmptyRPDisplayName
	}
	if config.Timeout <= 0 {
		return nil, ErrInvalidTimeout
	}

	configCopy := *config
	configCopy.RPID = normalizedRPID

	parsedOrigins, normalizedOrigins, err := parseConfiguredOrigins(config.RPOrigins, normalizedRPID, true)
	if err != nil {
		return nil, err
	}
	parsedRelated, normalizedRelated, err := parseConfiguredOrigins(config.RPRelatedOrigins, normalizedRPID, false)
	if err != nil {
		return nil, err
	}
	configCopy.RPOrigins = normalizedOrigins
	configCopy.RPRelatedOrigins = normalizedRelated
	parsedOrigins = append(parsedOrigins, parsedRelated...)

	if configCopy.Debug {
		log.Println("INFO: WebAuthn debug enabled, config:")
		log.Printf("%+v", configCopy)
	}

	return &WebAuthn{
		Config:          &configCopy,
		parsedRPOrigins: parsedOrigins,
	}, nil
}

// parseConfiguredOrigins parses and normalizes configured origins. With withinRPID set, every origin must be the host
// of the RP ID or a subdomain of it; related origins are exempt from that single rule and from nothing else.
func parseConfiguredOrigins(origins []string, rpid string, withinRPID bool) ([]parsedOriginData, []string, error) {
	parsed := make([]parsedOriginData, 0, len(origins))
	normalized := make([]string, 0, len(origins))
	for _, originStr := range origins {
		parsedOrigin, err := parseWebAuthnOrigin(originStr)
		if err != nil {
			return nil, nil, fmt.Errorf("%w %s: %w", ErrInvalidRPOrigin, originStr, err)
		}
		if withinRPID && !rpidMatchesOrigin(rpid, parsedOrigin) {
			return nil, nil, fmt.Errorf("%w: %s is not within %s", ErrRPIDOriginMismatch, parsedOrigin.hostname, rpid)
		}

		parsed = append(parsed, parsedOrigin)
		normalized = append(normalized, parsedOrigin.scheme+"://"+parsedOrigin.host)
	}
	return parsed, normalized, nil
}

// isAllowedOrigin checks if the configuration allows the provided origin.
// It compares the scheme and hostname case-insensitively using pre-parsed origins.
func (w *WebAuthn) isAllowedOrigin(origin string) (allowed bool, err error) {
	receivedOrigin, err := parseWebAuthnOrigin(origin)
	if err != nil {
		return false, fmt.Errorf("%w %s: %v", ErrParsingOrigin, origin, err)
	}

	// Check against pre-parsed configured origins
	for _, parsedOrigin := range w.parsedRPOrigins {
		if receivedOrigin.scheme == parsedOrigin.scheme && receivedOrigin.host == parsedOrigin.host {
			return true, nil
		}
	}
	return false, ErrOriginNotAllowed
}

// ParseWithB64 parses client data JSON and also returns the base64 encoded version
func (c *ClientData) ParseWithB64(jsonData string) (b64 []byte, err error) {
	b, err := decodeBase64URL(jsonData, MaxClientDataJSONSize, "client data JSON")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedUnmarshalClientData, err)
	}
	return b, nil
}
