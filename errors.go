package webauthn

import "errors"

var (
	ErrNilConfig                                   = errors.New("config cannot be nil")
	ErrNilInstance                                 = errors.New("webauthn instance is not initialized")
	ErrAttestationNotSupported                     = errors.New("unsupported attestation preference requested")
	ErrInvalidUserVerification                     = errors.New("invalid user verification preference in config")
	ErrInvalidRPOrigins                            = errors.New("invalid RP origins")
	ErrInvalidRPOrigin                             = errors.New("invalid RP origin")
	ErrEmptyRPID                                   = errors.New("RP ID cannot be empty")
	ErrEmptyRPDisplayName                          = errors.New("RP display name cannot be empty")
	ErrInvalidTimeout                              = errors.New("timeout must be greater than 0")
	ErrParsingOrigin                               = errors.New("error parsing origin")
	ErrOriginNotAllowed                            = errors.New("origin not allowed")
	ErrFailedUnmarshalClientData                   = errors.New("failed to unmarshal client data")
	ErrTypeNotWebauthnGet                          = errors.New("client data type is not webauthn.get")
	ErrTypeNotWebauthnCreate                       = errors.New("client data type is not webauthn.create")
	ErrFailedDecodeAuthData                        = errors.New("failed to decode authenticator data")
	ErrFailedParseAuthData                         = errors.New("failed to parse authenticator data")
	ErrFailedParseClientData                       = errors.New("failed to parse client data")
	ErrFailedDecodeClientData                      = errors.New("failed to decode client data")
	ErrRPIDHashMismatch                            = errors.New("RP ID hash mismatch")
	ErrUserPresentFlagNotSet                       = errors.New("flag User Present not set")
	ErrUserVerifiedFlagNotSet                      = errors.New("flag User Verified not set")
	ErrFailedDecodeSignature                       = errors.New("failed to decode signature")
	ErrSignatureVerification                       = errors.New("signature verification error")
	ErrInvalidSignature                            = errors.New("invalid signature")
	ErrSignatureCountMismatch                      = errors.New("signature count mismatch")
	ErrGeneratingChallenge                         = errors.New("error generating challenge")
	ErrFailedDecodeAttestationObject               = errors.New("failed to decode attestation object")
	ErrUnsupportedAttestationFormat                = errors.New("unsupported attestation format received")
	ErrMissingPublicKey                            = errors.New("missing public key")
	ErrInvalidPublicKey                            = errors.New("invalid public key format")
	ErrMissingCredentialID                         = errors.New("missing credential ID")
	ErrAuthDataTooShort                            = errors.New("auth data too short, expected at least 37 bytes")
	ErrAuthDataTooShortAttested                    = errors.New("auth data too short for attested credential data header")
	ErrAAGUIDToUUID                                = errors.New("error converting AAGUID to UUID")
	ErrAuthDataTooShortCredentialID                = errors.New("auth data too short for credential ID")
	ErrParsingCOSEKey                              = errors.New("error parsing COSE key data")
	ErrATFlagButNoData                             = errors.New("AT flag set, but no data remains for public key")
	ErrEDFlagButNoData                             = errors.New("ED flag set, but no data remains after parsing previous parts")
	ErrFailedDecodeExtensionData                   = errors.New("failed to decode extension data")
	ErrFailedUnmarshalPublicKeyCredential          = errors.New("failed to unmarshal public key credential")
	ErrFailedUnmarshalPublicKeyCredentialAssertion = errors.New("failed to unmarshal public key credential assertion")
)
