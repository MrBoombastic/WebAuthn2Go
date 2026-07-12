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

	if len(config.RPOrigins) == 0 {
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
	configCopy.RPOrigins = make([]string, 0, len(config.RPOrigins))

	parsedOrigins := make([]parsedOriginData, 0, len(config.RPOrigins))
	for _, originStr := range config.RPOrigins {
		parsedOrigin, err := parseWebAuthnOrigin(originStr)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %w", ErrInvalidRPOrigin, originStr, err)
		}
		if !rpidMatchesOrigin(normalizedRPID, parsedOrigin) {
			return nil, fmt.Errorf("%w: %s is not within %s", ErrRPIDOriginMismatch, parsedOrigin.hostname, normalizedRPID)
		}

		parsedOrigins = append(parsedOrigins, parsedOrigin)
		configCopy.RPOrigins = append(configCopy.RPOrigins, parsedOrigin.scheme+"://"+parsedOrigin.host)
	}

	if configCopy.Debug {
		log.Println("INFO: WebAuthn debug enabled, config:")
		log.Printf("%+v", configCopy)
	}

	return &WebAuthn{
		Config:          &configCopy,
		parsedRPOrigins: parsedOrigins,
	}, nil
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
