package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	webauthn "github.com/MrBoombastic/WebAuthn2Go"
)

var (
	errChallengeNotFound           = errors.New("challenge not found, expired, already consumed, or issued for another ceremony")
	errCredentialAlreadyRegistered = errors.New("user already has a credential")
	errSignCountConflict           = errors.New("stored signature counter changed concurrently")
)

type storedChallenge struct {
	Challenge string
	Email     string
	Ceremony  webauthn.CeremonyType
	ExpiresAt time.Time
}

func createTables() error {
	// Users
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id BLOB PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		display_name TEXT NOT NULL,
		cred_id TEXT,
		public_key BLOB,
		sign_count INTEGER DEFAULT 0
	)`)
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS users_credential_id ON users (cred_id) WHERE cred_id IS NOT NULL")
	if err != nil {
		return err
	}

	// Typed, expiring ceremony state. A separate table name intentionally
	// invalidates legacy challenge rows that lacked a ceremony type and expiry.
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS ceremony_challenges (
		challenge TEXT PRIMARY KEY,
		email TEXT NOT NULL,
		ceremony TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		CHECK (ceremony IN ('webauthn.create', 'webauthn.get'))
	)`)
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE INDEX IF NOT EXISTS ceremony_challenges_expiry ON ceremony_challenges (expires_at)")
	if err != nil {
		return err
	}

	return err
}

func saveUser(user *UserSessionData) error {
	_, err := db.Exec(
		"INSERT INTO users (id, email, display_name) VALUES (?, ?, ?)",
		user.User.ID, user.User.Name, user.User.DisplayName,
	)
	return err
}

func getUser(email string) (*UserSessionData, error) {
	row := db.QueryRow("SELECT id, email, display_name, cred_id, public_key, sign_count FROM users WHERE email = ?", email)

	var userData UserSessionData
	var userID []byte
	var credID sql.NullString
	var signCount uint32

	err := row.Scan(&userID, &userData.User.Name, &userData.User.DisplayName, &credID, &userData.PublicKey, &signCount)
	if err != nil {
		return nil, err
	}

	userData.User.ID = userID
	userData.SignCount = signCount

	if credID.Valid {
		userData.CredID = credID.String
	}

	return &userData, nil
}

func updateUserCredentials(email string, credID string, publicKeyBytes []byte, signCount uint32) error {
	result, err := db.Exec(
		"UPDATE users SET cred_id = ?, public_key = ?, sign_count = ? WHERE email = ? AND cred_id IS NULL AND public_key IS NULL",
		credID, publicKeyBytes, signCount, email,
	)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errCredentialAlreadyRegistered
	}
	return nil
}

func saveChallenge(challenge, email string, ceremony webauthn.CeremonyType, expiresAt time.Time) error {
	if !ceremony.IsValid() {
		return fmt.Errorf("invalid ceremony type %q", ceremony)
	}
	if !expiresAt.After(time.Now()) {
		return errors.New("challenge expiry must be in the future")
	}
	if _, err := db.Exec("DELETE FROM ceremony_challenges WHERE expires_at < ?", time.Now().UnixMilli()); err != nil {
		return err
	}
	_, err := db.Exec(
		"INSERT INTO ceremony_challenges (challenge, email, ceremony, expires_at) VALUES (?, ?, ?, ?)",
		challenge, email, ceremony, expiresAt.UnixMilli(),
	)
	return err
}

// getStoredChallenge returns the trusted challenge record matched by the
// client-provided value. Callers must pass record.Challenge, not the raw client
// value, to the WebAuthn verifier.
func getStoredChallenge(challenge string, ceremony webauthn.CeremonyType) (storedChallenge, error) {
	var record storedChallenge
	var expiresAt int64
	err := db.QueryRow(
		"SELECT challenge, email, ceremony, expires_at FROM ceremony_challenges WHERE challenge = ? AND ceremony = ? AND expires_at >= ?",
		challenge, ceremony, time.Now().UnixMilli(),
	).Scan(&record.Challenge, &record.Email, &record.Ceremony, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storedChallenge{}, errChallengeNotFound
	}
	if err != nil {
		return storedChallenge{}, err
	}
	record.ExpiresAt = time.UnixMilli(expiresAt)
	return record, err
}

// consumeStoredChallenge deletes exactly one record. DELETE is atomic in
// SQLite, so concurrent ceremony completions cannot both succeed.
func consumeStoredChallenge(challenge, email string, ceremony webauthn.CeremonyType) error {
	result, err := db.Exec(
		"DELETE FROM ceremony_challenges WHERE challenge = ? AND email = ? AND ceremony = ? AND expires_at >= ?",
		challenge, email, ceremony, time.Now().UnixMilli(),
	)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if deleted != 1 {
		return errChallengeNotFound
	}
	return nil
}

// commitLoginState consumes the authentication challenge and advances the
// signature counter in one transaction. A stale counter rolls the challenge
// deletion back so a valid concurrent response can be retried safely.
func commitLoginState(challenge, email string, ceremony webauthn.CeremonyType, credentialID string, previousSignCount, newSignCount uint32) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	result, err := tx.Exec(
		"DELETE FROM ceremony_challenges WHERE challenge = ? AND email = ? AND ceremony = ? AND expires_at >= ?",
		challenge, email, ceremony, time.Now().UnixMilli(),
	)
	if err != nil {
		return err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if deleted != 1 {
		return errChallengeNotFound
	}

	result, err = tx.Exec(
		"UPDATE users SET sign_count = ? WHERE email = ? AND cred_id = ? AND sign_count = ?",
		newSignCount, email, credentialID, previousSignCount,
	)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errSignCountConflict
	}
	return tx.Commit()
}

func deleteChallenge(challenge, email string, ceremony webauthn.CeremonyType) error {
	_, err := db.Exec(
		"DELETE FROM ceremony_challenges WHERE challenge = ? AND email = ? AND ceremony = ?",
		challenge, email, ceremony,
	)
	return err
}

func userExists(email string) (bool, error) {
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM users WHERE email = ?",
		email,
	).Scan(&count)
	return count > 0, err
}
