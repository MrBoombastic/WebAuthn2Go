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

func TestCommitRegistrationStateIsAtomic(t *testing.T) {
	withTestDB(t)
	first := &UserSessionData{User: webauthn.UserEntity{ID: []byte("first-user"), Name: "first@example.com", DisplayName: "First"}}
	if err := saveUser(first); err != nil {
		t.Fatalf("saveUser(first) error = %v", err)
	}
	if err := saveChallenge("first-registration", first.User.Name, webauthn.CeremonyRegistration, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("saveChallenge(first) error = %v", err)
	}
	credential := webauthn.RegistrationResult{CredentialID: "credential", PublicKey: []byte("public-key"), SignCount: 3}
	if err := commitRegistrationState("first-registration", first.User.Name, webauthn.CeremonyRegistration, credential); err != nil {
		t.Fatalf("commitRegistrationState(first) error = %v", err)
	}
	if _, err := getStoredChallenge("first-registration", webauthn.CeremonyRegistration); !errors.Is(err, errChallengeNotFound) {
		t.Fatalf("successful commit must consume challenge, got %v", err)
	}
	storedFirst, err := getUser(first.User.Name)
	if err != nil {
		t.Fatalf("getUser(first) error = %v", err)
	}
	if storedFirst.CredID != credential.CredentialID || string(storedFirst.PublicKey) != string(credential.PublicKey) || storedFirst.SignCount != credential.SignCount {
		t.Fatalf("credential was not stored atomically: %#v", storedFirst)
	}

	second := &UserSessionData{User: webauthn.UserEntity{ID: []byte("second-user"), Name: "second@example.com", DisplayName: "Second"}}
	if err := saveUser(second); err != nil {
		t.Fatalf("saveUser(second) error = %v", err)
	}
	if err := saveChallenge("conflicting-registration", second.User.Name, webauthn.CeremonyRegistration, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("saveChallenge(conflict) error = %v", err)
	}
	if err := commitRegistrationState("conflicting-registration", second.User.Name, webauthn.CeremonyRegistration, credential); err == nil {
		t.Fatal("expected duplicate credential commit to fail")
	}
	if _, err := getStoredChallenge("conflicting-registration", webauthn.CeremonyRegistration); err != nil {
		t.Fatalf("failed credential write must roll challenge consumption back: %v", err)
	}
	storedSecond, err := getUser(second.User.Name)
	if err != nil {
		t.Fatalf("getUser(second) error = %v", err)
	}
	if storedSecond.CredID != "" || len(storedSecond.PublicKey) != 0 {
		t.Fatalf("failed commit must not partially store credential: %#v", storedSecond)
	}
}

func TestCommitLoginStateIsAtomicAndCompareAndSwapsCounter(t *testing.T) {
	withTestDB(t)
	user := &UserSessionData{User: webauthn.UserEntity{ID: []byte("user-id"), Name: "user@example.com", DisplayName: "User"}}
	if err := saveUser(user); err != nil {
		t.Fatalf("saveUser() error = %v", err)
	}
	if err := saveChallenge("registration-setup", user.User.Name, webauthn.CeremonyRegistration, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("saveChallenge(registration setup) error = %v", err)
	}
	if err := commitRegistrationState("registration-setup", user.User.Name, webauthn.CeremonyRegistration, webauthn.RegistrationResult{
		CredentialID: "credential",
		PublicKey:    []byte("public-key"),
	}); err != nil {
		t.Fatalf("commitRegistrationState(setup) error = %v", err)
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
