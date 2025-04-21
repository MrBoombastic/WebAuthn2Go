package main

import (
	"database/sql"
	webauthn "github.com/MrBoombastic/WebAuthn2Go"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/google/uuid"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

var (
	w  *webauthn.WebAuthn
	db *sql.DB
)

// UserSessionData holds the user entity and their credential details for this example.
type UserSessionData struct {
	User      webauthn.UserEntity
	CredID    string
	PublicKey []byte
	SignCount uint32
}

// sendJSONError sends a JSON error response with a specific status code.
func sendJSONError(c *fiber.Ctx, statusCode int, message string, err error) error {
	log.Printf("Error: %s (Detail: %v)", message, err)
	return c.Status(statusCode).JSON(fiber.Map{
		"error": message,
	})
}

func main() {
	var err error
	// Initialize WebAuthn library
	// Relying Party configuration MUST match the client-side
	// RPOrigin, and RPID should be based on your actual domain.
	w, err = webauthn.New(&webauthn.Config{
		RPID:             "localhost",                       // Domain name only - must match the domain in your URL
		RPDisplayName:    "WebAuthn2Go Example",             // Display name
		RPOrigins:        []string{"http://localhost:8080"}, // Allowed origins - with protocol and port
		Timeout:          300_000,                           // Milliseconds, 5 minutes, recommended default value if userVerification is preferred or required, 2 mins if discouraged
		UserVerification: webauthn.UVPreferred,              // User verification requirement
		Attestation:      webauthn.AttestationIndirect,      // Attestation preference, Indirect gives us AAGUID
		Debug:            true,                              // Enable debug logging
	})
	if err != nil {
		log.Fatalf("Failed to initialize WebAuthn: %v", err)
	}

	// Init SQLite database
	db, err = sql.Open("sqlite3", "./webauthn.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Create tables
	err = createTables()
	if err != nil {
		log.Fatalf("Failed to create database tables: %v", err)
	}

	// Initialize Fiber app
	app := fiber.New(fiber.Config{AppName: "WebAuthn2Go", DisableStartupMessage: true})

	app.Use(logger.New())
	app.Use(recover.New())

	// Define routes
	app.Post("/register/begin", beginRegistration)
	app.Post("/register/finish", finishRegistration)
	app.Post("/login/begin", beginLogin)
	app.Post("/login/finish", finishLogin)

	// Serve static
	app.Static("/", "./static")

	port := ":8080"
	log.Printf("Starting example server on http://localhost%s", port)
	log.Fatal(app.Listen(port))
}

// /register/begin endpoint
func beginRegistration(c *fiber.Ctx) error {
	// 1. Parse request body for username and email
	var reqBody struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	// Using fiber's BodyParser to parse the request body
	if err := c.BodyParser(&reqBody); err != nil {
		return sendJSONError(c, fiber.StatusBadRequest, "Failed to parse request body", err)
	}
	if reqBody.Username == "" || reqBody.Email == "" {
		return sendJSONError(c, fiber.StatusBadRequest, "Username and email are required", nil)
	}

	// 2. Check if user already exists. This is a simple example, so privacy is not a concern.
	exists, err := userExists(reqBody.Email)
	if err != nil {
		return sendJSONError(c, fiber.StatusInternalServerError, "Failed to check user existence", err)
	}
	if exists {
		return sendJSONError(c, fiber.StatusConflict, "Email already registered", nil)
	}

	// 3. Generate user ID (UUIDv4)
	userID := uuid.New()

	// 4. Create UserEntity
	newUser := webauthn.UserEntity{
		ID:          userID[:],
		Name:        reqBody.Email,
		DisplayName: reqBody.Username,
	}

	// 5. Create and store user session data
	err = saveUser(&UserSessionData{User: newUser})
	if err != nil {
		return sendJSONError(c, fiber.StatusInternalServerError, "Failed to save user", err)
	}

	log.Printf("Begin Registration - User: %s - %s", newUser.DisplayName, newUser.Name)

	// 6. Call library's BeginRegistration
	opts, err := w.BeginRegistration(newUser)
	if err != nil {
		return sendJSONError(c, fiber.StatusInternalServerError, "Failed to begin registration", err)
	}

	// 7. Store challenge
	err = saveChallenge(opts.Challenge, newUser.Name)
	if err != nil {
		return sendJSONError(c, fiber.StatusInternalServerError, "Failed to save challenge", err)
	}
	log.Printf("Stored active challenge for %s: %s...", newUser.Name, opts.Challenge[:10])

	log.Printf("Begin Registration - Options generated for RP ID: %+v\n", w)
	return c.JSON(opts)
}

// /register/finish endpoint
func finishRegistration(c *fiber.Ctx) error {
	// 1. Parse request payload
	var payload webauthn.PublicKeyCredential
	// Using library's method to parse the request body
	err := payload.Parse(c.Body())
	if err != nil {
		return sendJSONError(c, fiber.StatusBadRequest, "Failed to parse request body", err)
	}

	// 2. Extract challenge and find associated email, DO NOT go further if challenge is mismatched
	email, err := getEmailByChallenge(payload.ClientData().Challenge)
	if err != nil {
		log.Printf("Challenge not found or expired: %s", payload.ClientData().Challenge[:10])
		return sendJSONError(c, fiber.StatusBadRequest, "Registration challenge not found or expired", nil)
	}
	log.Printf("Found active challenge for email: %s", email)

	// 3. Retrieve user session data
	sessionData, err := getUser(email)
	if err != nil {
		log.Printf("User session not found for email: %s, although challenge existed.", email)
		deleteChallenge(payload.ClientData().Challenge) // clear dangling challenge
		return sendJSONError(c, fiber.StatusInternalServerError, "User session data not found", nil)
	}

	log.Printf("Finish Registration - User: %s, Email: %s, Credential ID: %s", sessionData.User.DisplayName, email, payload.ID)

	// 4. Prepare data for the library
	registrationData := webauthn.RegistrationData{
		ClientDataJSON:    payload.ClientDataJSON,
		AttestationObject: payload.AttestationObject,
	}

	// 5. Call library
	result, err := w.FinishRegistration(registrationData)
	if err != nil {
		// clear challenge if registration fails
		deleteChallenge(payload.ClientData().Challenge)
		log.Printf("FinishRegistration failed for email %s: %v", email, err)
		return sendJSONError(c, fiber.StatusBadRequest, "Registration verification failed", err)
	}

	// 6. Store the credential details in the database
	err = updateUserCredentials(email, result.CredentialID, result.PublicKey, result.SignCount)
	if err != nil {
		deleteChallenge(payload.ClientData().Challenge)
		return sendJSONError(c, fiber.StatusInternalServerError, "Failed to store credentials", err)
	}

	log.Printf("Registration successful for %s (%s)! Stored CredID: %s, AAGUID: %s, Name: %s", sessionData.User.DisplayName, email, payload.ID, result.AAGUID, result.AuthenticatorName)

	// 8. clear active challenge
	err = deleteChallenge(payload.ClientData().Challenge)
	if err != nil {
		log.Printf("Warning: Failed to delete challenge: %v", err)
	}
	log.Printf("Removed active challenge for %s", email)

	// 9. Reply to the client
	return c.JSON(fiber.Map{
		"success":           true,
		"authenticatorName": result.AuthenticatorName,
		"aaguid":            result.AAGUID,
	})
}

// /login/begin endpoint
func beginLogin(c *fiber.Ctx) error {
	// 1. Parse request body for email
	var reqBody struct {
		Email string `json:"email"`
	}
	// Using fiber's BodyParser to parse the request body
	if err := c.BodyParser(&reqBody); err != nil {
		return sendJSONError(c, fiber.StatusBadRequest, "Failed to parse request body", err)
	}
	if reqBody.Email == "" {
		return sendJSONError(c, fiber.StatusBadRequest, "Email is required", nil)
	}

	// 2. Retrieve user session data
	sessionData, err := getUser(reqBody.Email)
	if err != nil {
		log.Printf("Login attempt for unregistered email: %s", reqBody.Email)
		return sendJSONError(c, fiber.StatusNotFound, "User not found.", nil)
	}

	// 3. Check if user has a credential registered, you should handle that differently in production
	if sessionData.CredID == "" || sessionData.PublicKey == nil {
		log.Printf("Login attempt for user %s with no registered credential.", sessionData.User.DisplayName)
		return sendJSONError(c, fiber.StatusBadRequest, "No credential registered for this user.", nil)
	}

	log.Printf("Begin Login - User: %s, Email: %s", sessionData.User.DisplayName, reqBody.Email)

	// 4. Call library's BeginLogin
	opts, err := w.BeginLogin([]string{sessionData.CredID})
	if err != nil {
		log.Printf("BeginLogin failed for user %s: %v", sessionData.User.DisplayName, err)
		return sendJSONError(c, fiber.StatusInternalServerError, "Failed to begin login", err)
	}

	// 5. Store challenge
	err = saveChallenge(opts.Challenge, reqBody.Email)
	if err != nil {
		return sendJSONError(c, fiber.StatusInternalServerError, "Failed to save challenge", err)
	}

	log.Printf("Stored active login challenge for %s: %s...", reqBody.Email, opts.Challenge[:10])
	log.Printf("Begin Login - Options generated for RP ID: %s", opts.RPID)
	return c.JSON(opts)
}

// /login/finish endpoint
func finishLogin(c *fiber.Ctx) error {
	// 1. Parse request payload
	var payload webauthn.PublicKeyCredentialAssertion
	// Using library's method to parse the request body
	err := payload.Parse(c.Body())
	if err != nil {
		return sendJSONError(c, fiber.StatusBadRequest, "Failed to parse request body", err)
	}

	// 2. Extract challenge and find associated email
	email, err := getEmailByChallenge(payload.GetChallenge())
	if err != nil {
		log.Printf("Login challenge not found or expired: %s...", payload.GetChallenge()[:10])
		return sendJSONError(c, fiber.StatusBadRequest, "Login challenge expired or not found", nil)
	}
	log.Printf("Found active login challenge for email: %s", email)

	// 3. Retrieve user session data
	sessionData, err := getUser(email)
	if err != nil {
		log.Printf("User session not found for email: %s, although challenge existed.", email)
		deleteChallenge(payload.GetChallenge()) // clear
		return sendJSONError(c, fiber.StatusInternalServerError, "User session data not found during login finish", nil)
	}

	log.Printf("Finish Login - User: %s, Email: %s, Credential ID: %s", sessionData.User.DisplayName, email, payload.ID)

	// 4. Verify credential ID matches stored ID
	if payload.ID != sessionData.CredID {
		log.Printf("Credential ID mismatch for user %s. Expected: %s, Got: %s", sessionData.User.DisplayName, sessionData.CredID, payload.ID)
		deleteChallenge(payload.GetChallenge()) // clear challenge
		return sendJSONError(c, fiber.StatusBadRequest, "Credential ID mismatch", nil)
	}

	// 5. Prepare data for the library
	loginData := webauthn.LoginData{
		ClientDataJSON:  payload.ClientDataJSON,
		AuthData:        payload.AuthenticatorData,
		Signature:       payload.Signature,
		StoredSignCount: sessionData.SignCount,
		PublicKey:       sessionData.PublicKey,
	}

	// 6. Call library function
	result, err := w.FinishLogin(&loginData)
	if err != nil {
		// clear challenge if login fails
		deleteChallenge(payload.GetChallenge())
		log.Printf("FinishLogin failed for user %s: %v", sessionData.User.DisplayName, err)
		return sendJSONError(c, fiber.StatusBadRequest, "Login verification failed", err)
	}

	// 7. Update sign count in database
	err = updateSignCount(email, result.NewSignCount)
	if err != nil {
		log.Printf("Warning: Failed to update sign count: %v", err)
	}
	log.Printf("Login successful for %s (%s)! New Sign Count: %d, User Verified: %t",
		sessionData.User.DisplayName, email, result.NewSignCount, result.UserVerified)

	// 8. Clear the challenge
	err = deleteChallenge(payload.GetChallenge())
	if err != nil {
		log.Printf("Warning: Failed to delete challenge: %v", err)
	}
	log.Printf("Removed active login challenge for %s", email)

	// 9. Respond to client
	return c.JSON(fiber.Map{
		"success":      true,
		"userVerified": result.UserVerified,
		"username":     sessionData.User.DisplayName,
	})
}
