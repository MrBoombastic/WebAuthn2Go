package main

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	webauthn "github.com/MrBoombastic/WebAuthn2Go"
)

func TestConsumeStoredChallengeIsSingleUse(t *testing.T) {
	originalDB := db
	t.Cleanup(func() { db = originalDB })

	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	testDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = testDB.Close() })
	db = testDB

	if err := createTables(); err != nil {
		t.Fatalf("createTables() error = %v", err)
	}
	if err := saveChallenge("trusted-challenge", "user@example.com", webauthn.CeremonyRegistration, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("saveChallenge() error = %v", err)
	}

	if _, err := getStoredChallenge("trusted-challenge", webauthn.CeremonyAuthentication); !errors.Is(err, errChallengeNotFound) {
		t.Fatalf("login must not accept a registration challenge, got %v", err)
	}

	record, err := getStoredChallenge("trusted-challenge", webauthn.CeremonyRegistration)
	if err != nil {
		t.Fatalf("getStoredChallenge() error = %v", err)
	}
	if record.Challenge != "trusted-challenge" || record.Email != "user@example.com" {
		t.Fatalf("unexpected record: %#v", record)
	}

	if err := consumeStoredChallenge(record.Challenge, record.Email, record.Ceremony); err != nil {
		t.Fatalf("first consumeStoredChallenge() error = %v", err)
	}
	if err := consumeStoredChallenge(record.Challenge, record.Email, record.Ceremony); !errors.Is(err, errChallengeNotFound) {
		t.Fatalf("expected errChallengeNotFound on second consume, got %v", err)
	}
}

func TestExpiredChallengeIsRejected(t *testing.T) {
	withTestDB(t)
	_, err := db.Exec(
		"INSERT INTO ceremony_challenges (challenge, email, ceremony, expires_at) VALUES (?, ?, ?, ?)",
		"expired", "user@example.com", webauthn.CeremonyAuthentication, time.Now().Add(-time.Minute).UnixMilli(),
	)
	if err != nil {
		t.Fatalf("insert expired challenge: %v", err)
	}
	if _, err := getStoredChallenge("expired", webauthn.CeremonyAuthentication); !errors.Is(err, errChallengeNotFound) {
		t.Fatalf("expected expired challenge rejection, got %v", err)
	}
}

func TestCommitLoginStateIsAtomicAndCompareAndSwapsCounter(t *testing.T) {
	withTestDB(t)
	user := &UserSessionData{User: webauthn.UserEntity{ID: []byte("user-id"), Name: "user@example.com", DisplayName: "User"}}
	if err := saveUser(user); err != nil {
		t.Fatalf("saveUser() error = %v", err)
	}
	if err := updateUserCredentials(user.User.Name, "credential", []byte("public-key"), 0); err != nil {
		t.Fatalf("updateUserCredentials() error = %v", err)
	}
	if err := saveChallenge("counterless", user.User.Name, webauthn.CeremonyAuthentication, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("saveChallenge(counterless) error = %v", err)
	}
	if err := commitLoginState("counterless", user.User.Name, webauthn.CeremonyAuthentication, "credential", 0, 0); err != nil {
		t.Fatalf("counterless authenticators must be committable: %v", err)
	}
	if err := saveChallenge("first", user.User.Name, webauthn.CeremonyAuthentication, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("saveChallenge(first) error = %v", err)
	}
	if err := saveChallenge("stale", user.User.Name, webauthn.CeremonyAuthentication, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("saveChallenge(stale) error = %v", err)
	}

	if err := commitLoginState("first", user.User.Name, webauthn.CeremonyAuthentication, "credential", 0, 1); err != nil {
		t.Fatalf("commitLoginState(first) error = %v", err)
	}
	if err := commitLoginState("stale", user.User.Name, webauthn.CeremonyAuthentication, "credential", 0, 2); !errors.Is(err, errSignCountConflict) {
		t.Fatalf("expected errSignCountConflict, got %v", err)
	}
	if _, err := getStoredChallenge("stale", webauthn.CeremonyAuthentication); err != nil {
		t.Fatalf("counter conflict must roll challenge consumption back: %v", err)
	}
	stored, err := getUser(user.User.Name)
	if err != nil {
		t.Fatalf("getUser() error = %v", err)
	}
	if stored.SignCount != 1 {
		t.Fatalf("expected sign count 1, got %d", stored.SignCount)
	}
}

func withTestDB(t *testing.T) {
	t.Helper()
	originalDB := db
	t.Cleanup(func() { db = originalDB })

	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	testDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = testDB.Close() })
	db = testDB
	if err := createTables(); err != nil {
		t.Fatalf("createTables() error = %v", err)
	}
}
