package webauthn

// Constants for COSE Algorithms
const (
	algES256 int64 = -7   // ECDSA w/ SHA-256
	algRS256 int64 = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
)

// AttestationPreference defines the level of attestation requested.
type AttestationPreference string

const (
	AttestationNone     AttestationPreference = "none"
	AttestationIndirect AttestationPreference = "indirect"
	AttestationPacked   AttestationPreference = "packed"
)

// IsValid checks if the AttestationPreference is one of the defined constants.
func (ap AttestationPreference) IsValid() bool {
	switch ap {
	case AttestationNone, AttestationIndirect, AttestationPacked:
		return true
	default:
		return false
	}
}

// UserVerificationRequirement defines the requirement level for user verification.
type UserVerificationRequirement string

const (
	UVRequired    UserVerificationRequirement = "required"
	UVPreferred   UserVerificationRequirement = "preferred"
	UVDiscouraged UserVerificationRequirement = "discouraged"
)

// IsValid checks if the UserVerificationRequirement is one of the defined constants.
func (uv UserVerificationRequirement) IsValid() bool {
	switch uv {
	case UVRequired, UVPreferred, UVDiscouraged:
		return true
	default:
		return false
	}
}

// Config holds the configuration for the WebAuthn library.
// Ensure RPOrigin(s) are set correctly for security checks.
type Config struct {
	RPID             string                      // Relying Party ID (e.g., "example.com")
	RPDisplayName    string                      // Relying Party display name (e.g., "Example Corp")
	RPOrigins        []string                    // Allowed origins for RP assertions (e.g., ["https://example.com", "https://login.example.com:2137"])
	Timeout          uint32                      // Default timeout for operations (milliseconds)
	UserVerification UserVerificationRequirement // Default User Verification Requirement
	Attestation      AttestationPreference       // Default Attestation Preference
	Debug            bool                        // Enable debug logging
}

// WebAuthn struct holds the configuration and manages WebAuthn operations.
type WebAuthn struct {
	Config          *Config
	parsedRPOrigins []parsedOriginData // Pre-parsed origins for efficient checking
}

// parsedOriginData holds pre-parsed and normalized components of an allowed origin.
// Internal struct to avoid exposing parsing details.
type parsedOriginData struct {
	scheme string
	host   string
}

// RegistrationData holds the inputs for completing a registration ceremony.
type RegistrationData struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string
}

// RegistrationResult holds the successful result of a registration ceremony.
type RegistrationResult struct {
	CredentialID      string
	PublicKey         []byte
	AAGUID            string
	AuthenticatorName string
	SignCount         uint32
}

// LoginResult holds the successful result of an authentication (login) ceremony.
type LoginResult struct {
	NewSignCount uint32 `json:"newSignCount"`
	UserVerified bool   `json:"userVerified"`
}

// ValidationOutput holds results from the internal validateAssertion method.
type ValidationOutput struct {
	NewSignCount uint32 `json:"newSignCount"`
	UserVerified bool   `json:"userVerified"`
}

// UserEntity represents the user entity
type UserEntity struct {
	ID          []byte `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// CredentialParameter defines a credential parameter
type CredentialParameter struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

// BeginRegistrationOptions holds options for navigator.credentials.create()
type BeginRegistrationOptions struct {
	Challenge        string                      `json:"challenge"`
	RP               RelyingPartyEntity          `json:"rp"`
	User             UserEntity                  `json:"user"`
	PubKeyCredParams []CredentialParameter       `json:"pubKeyCredParams"`
	Timeout          uint32                      `json:"timeout"`
	Attestation      AttestationPreference       `json:"attestation"`
	UserVerification UserVerificationRequirement `json:"userVerification,omitempty"`
}

type RelyingPartyEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PublicKeyCredentialDescriptor defines allowed credentials for login
type PublicKeyCredentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// PublicKeyCredentialRequestOptions holds options for navigator.credentials.get()
type PublicKeyCredentialRequestOptions struct {
	Challenge        string                          `json:"challenge"`
	Timeout          uint32                          `json:"timeout"`
	RPID             string                          `json:"rpId"`
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials"`
	UserVerification UserVerificationRequirement     `json:"userVerification"`
}

type attestationObject struct {
	AuthData []byte                 `cbor:"authData"`
	Fmt      string                 `cbor:"fmt"`
	AttStmt  map[string]interface{} `cbor:"attStmt"` // We don't parse/verify this for "packed" or "indirect" anyway
}

// ClientData represents the common structure of client data in both registration and login
type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	RPOrigin  string `json:"origin"`
	//CrossOrigin bool   `json:"crossOrigin"` todo: support this
}

type LoginData struct {
	ClientDataJSON  string `json:"clientDataJSON"`
	AuthData        string `json:"authData"`
	Signature       string `json:"signature"`
	StoredSignCount uint32 `json:"storedSignCount"`
	PublicKey       []byte `json:"publicKey"`
}
