package main

import (
	"database/sql"
)

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

	// Challenges
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS challenges (
		challenge TEXT PRIMARY KEY,
		email TEXT NOT NULL
	)`)

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
	_, err := db.Exec("UPDATE users SET cred_id = ?, public_key = ?, sign_count = ? WHERE email = ?", credID, publicKeyBytes, signCount, email)
	return err
}

func updateSignCount(email string, newSignCount uint32) error {
	_, err := db.Exec("UPDATE users SET sign_count = ? WHERE email = ?", newSignCount, email)
	return err
}

func saveChallenge(challenge, email string) error {
	_, err := db.Exec("INSERT INTO challenges (challenge, email) VALUES (?, ?)", challenge, email)
	return err
}

func getEmailByChallenge(challenge string) (string, error) {
	var email string
	err := db.QueryRow(
		"SELECT email FROM challenges WHERE challenge = ?",
		challenge,
	).Scan(&email)
	return email, err
}

func deleteChallenge(challenge string) error {
	_, err := db.Exec(
		"DELETE FROM challenges WHERE challenge = ?",
		challenge,
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
