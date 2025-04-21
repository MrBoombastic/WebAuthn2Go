package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2/log"
	"net/url"
	"strings"
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
	if config.RPDisplayName == "" {
		return nil, ErrEmptyRPDisplayName
	}
	if config.Timeout <= 0 {
		return nil, ErrInvalidTimeout
	}

	parsedOrigins := make([]parsedOriginData, 0, len(config.RPOrigins))
	for _, originStr := range config.RPOrigins {
		u, err := url.Parse(originStr)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %w", ErrInvalidRPOrigin, originStr, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("%w %s: missing scheme or host", ErrInvalidRPOrigin, originStr)
		}
		parsedOrigins = append(parsedOrigins, parsedOriginData{
			scheme: strings.ToLower(u.Scheme),
			host:   strings.ToLower(u.Host),
		})
	}

	if config.Debug {
		log.Debug("INFO: WebAuthn debug enabled, config:")
		log.Debugf("%+v", *config)
	}

	return &WebAuthn{
		Config:          config,
		parsedRPOrigins: parsedOrigins,
	}, nil
}

// isAllowedOrigin checks if the configuration allows the provided origin.
// It compares the scheme and hostname case-insensitively using pre-parsed origins.
func (w *WebAuthn) isAllowedOrigin(origin string) (allowed bool, err error) {
	receivedURL, err := url.Parse(origin)
	if err != nil {
		return false, fmt.Errorf("%w %s: %v", ErrParsingOrigin, origin, err)
	}

	// Normalize to be safe
	receivedScheme := strings.ToLower(receivedURL.Scheme)
	receivedHost := strings.ToLower(receivedURL.Host)

	// Check against pre-parsed configured origins
	for _, parsedOrigin := range w.parsedRPOrigins {
		if receivedScheme == parsedOrigin.scheme && receivedHost == parsedOrigin.host {
			return true, nil
		}
	}
	return false, ErrOriginNotAllowed
}

// ParseWithB64 parses client data JSON and also returns the base64 encoded version
func (c *ClientData) ParseWithB64(jsonData string) (b64 []byte, err error) {
	b, err := base64.RawURLEncoding.DecodeString(jsonData)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedUnmarshalClientData, err)
	}
	return b, nil
}
