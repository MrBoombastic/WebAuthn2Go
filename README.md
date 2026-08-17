# WebAuthn2Go – Go WebAuthn Server Library

![docs/hero.jpg](docs/hero.jpg)

[![Go Reference](https://pkg.go.dev/badge/github.com/MrBoombastic/WebAuthn2Go.svg)](https://pkg.go.dev/github.com/MrBoombastic/WebAuthn2Go)

A Go library designed to simplify the server-side implementation of the WebAuthn (FIDO2) protocol for passwordless
authentication.

## Features

* **WebAuthn Server Logic:** Handles core server-side registration and authentication ceremonies.
* **Attestation Support:**
    * Accepts `none`, `indirect`, and `packed` attestation formats.
        * Currently, **skips cryptographic verification** of attestation statements (`AttStmt`), focusing on extracting
          authenticator data (`AuthData`) including AAGUID and Public Key.
* **Assertion Verification:** Validates login assertions including challenge, origin, RP ID, user presence/verification
  flags, and signature.
* **Sign Count Protection:** Checks for increasing sign counts to help prevent replay attacks (requires secure storage
  by the caller).
* **AAGUID Lookup:** Provides a utility to look up authenticator names based on AAGUID.
* **Extension Support:** Basic support for WebAuthn extensions.
* **Configuration:** Simple configuration for Relying Party details.

## Why this library?

This library is designed to be easy to use and integrate into existing Go applications. You don't need to especially
implement custom interfaces or convert your Fiber's `fasthttp.Request` into `http.Request`, like
in https://github.com/go-webauthn/webauthn. There are no other alternatives, except
the https://github.com/egregors/passkey, which is a wrapper around the first one, which additionally can set cookies for
you.

If you want more flexibility or control, and you don't need fancy features, this is the library for You.

## Why NOT this library?

This library is not intended to be a full-fledged WebAuthn implementation. It does not handle attestation verification,
for example. This library is also in early development, so may be not suitable for production use yet.

The library is also not popular. It's possible that this repo has more or less zero stars and has never been reviewed or
used by the third party. So, if you are looking for a battle-tested library, this is not the one.

One more thing – **the code is written with the partial help of AI**. Although the author tried his best to understand
WebAuthn
specification and read various sources, the code may be far from perfect or even insecure. Every line of code has been
read and verified by myself. It wasn't just *do webauthn lib wololo* in ChatGPT. But still, please use it at your own
risk.

Used sources:

- https://www.corbado.com/glossary/attestation and other glossary entries – readable, but sometimes too simple
- https://webauthn.guide/ – general overview
- https://www.w3.org/TR/webauthn/ – THE specification

> [!WARNING]
> This library requires Go 1.25 or newer.

## Installation

```bash
go get github.com/MrBoombastic/WebAuthn2Go
```

## Try the working demo first

The easiest way to understand the library is to run the included example from a clone of this repository:

```bash
cd example
go run .
```

Then open [http://localhost:8080](http://localhost:8080), enter any name and email address, and click **Register**. Your
browser or security key will ask you to create a passkey. After that, click **Login** to authenticate with it.

The demo uses Fiber and SQLite, but the WebAuthn library itself is not tied to either of them. Its complete server code
is in [example/example.go](./example/example.go), the database code is in [example/db.go](./example/db.go), and the
browser-side WebAuthn calls are in [example/static/script.js](./example/static/script.js).

> [!WARNING]
> The example is intended for local learning. It is not a production-ready account system.

## Configuration

Before using the library, you need to configure your Relying Party (RP) details and other minor settings.

```go
w, err := webauthn.New(&webauthn.Config{
    RPID:             "localhost",                    // Domain only, without http:// or a port.
    RPDisplayName:    "My first passkey app",         // Name shown by the browser.
    RPOrigins:        []string{"http://localhost:8080"}, // Exact URL used in the browser.
    Timeout:          300_000,                        // Five minutes, in milliseconds.
    UserVerification: webauthn.UVPreferred,           // Use PIN/biometrics when available.
    Attestation:      webauthn.AttestationNone,       // Recommended when device provenance is not needed.
    Debug:            true,
})
if err != nil {
	log.Fatalf("Failed to initialize WebAuthn: %v", err)
}
```

> [!IMPORTANT]
> * `RPID` **must** be the effective domain of your web application. Browsers enforce this strictly.
> * `RPOrigins` **must** include all origins (scheme + host + port if non-default) from which WebAuthn requests will
    originate. Mismatched origins will cause browser errors.

## Usage Overview

### WebAuthn in plain English

WebAuthn has two flows, called ceremonies:

1. **Registration:** your server gives the browser a random, one-time challenge. The browser creates a passkey and
   returns a public key. Your server verifies the response and stores that public key.
2. **Login:** your server sends a new challenge. The authenticator signs it with a private key never sent to your
   server. Your server checks the signature using the stored public key.

The challenge prevents an old response from being replayed. It must be stored by the server, expire after a short time,
and be usable only once. Do not trust a challenge, user ID, public key, or signature merely because the browser sent it.

The four main methods map directly to those two flows:

| Flow         | Send options to the browser | Verify the browser response |
|--------------|-----------------------------|-----------------------------|
| Registration | `BeginRegistration`         | `FinishRegistration`        |
| Login        | `BeginLogin`                | `FinishLogin`               |

Your HTTP framework only transports JSON. The important state—challenges, users, credentials, and signature counters—
belongs in your server-side database.

### Registration example

Starting registration is simple. Create the browser options and save the generated challenge with the user it belongs
to:

```go
user := webauthn.UserEntity{
	ID:          []byte("stable-random-user-id"), // Use a stable opaque ID from your database.
	Name:        "alice@example.com",
	DisplayName: "Alice",
}

options, err := w.BeginRegistration(user)
if err != nil {
	return err
}

// Store this on the server before returning options as JSON to the browser.
err = store.SaveChallenge(
	options.Challenge,
	user.ID,
	webauthn.CeremonyRegistration,
	time.Now().Add(5*time.Minute),
)
if err != nil {
	return err
}

returnJSON(options)
```

When the browser returns its response, retrieve the trusted challenge and finish registration. The callback must delete
the challenge and insert the verified credential in **one database transaction**:

```go
var response webauthn.PublicKeyCredential
if err := response.Parse(requestBody); err != nil {
	return err
}

// Find the server-side record using the challenge reported in clientDataJSON.
pending, err := store.FindChallenge(
	response.ClientData().Challenge,
	webauthn.CeremonyRegistration,
)
if err != nil {
	return err // Missing, expired, already used, or wrong ceremony.
}

result, err := w.FinishRegistration(
	webauthn.RegistrationData{
		ClientDataJSON:    response.ClientDataJSON,
		AttestationObject: response.AttestationObject,
	},
	pending.Challenge, // Trusted value loaded from the server-side store.
	func(challenge string, ceremony webauthn.CeremonyType, credential webauthn.RegistrationResult) error {
		// This method must atomically:
		// 1. delete the matching unexpired challenge, and
		// 2. insert credential.CredentialID, PublicKey, and SignCount for pending.UserID.
		return store.CommitRegistration(pending.UserID, challenge, ceremony, credential)
	},
)
if err != nil {
	return err
}

log.Printf("registered credential %s", result.CredentialID)
```

`store.SaveChallenge`, `store.FindChallenge`, `store.CommitRegistration`, and `returnJSON` are deliberately descriptive
placeholders for your own database and HTTP code. A concrete SQLite implementation is available in
[example/db.go](./example/db.go).

### Login example

To begin login, load the user's credential ID, create options, and store the new challenge:

```go
credential, err := store.CredentialForUser("alice@example.com")
if err != nil {
	return err
}

options, err := w.BeginLogin([]string{credential.ID})
if err != nil {
	return err
}
if err := store.SaveChallenge(
	options.Challenge,
	credential.UserHandle,
	webauthn.CeremonyAuthentication,
	time.Now().Add(5*time.Minute),
); err != nil {
	return err
}

returnJSON(options)
```

After the browser signs the challenge, verify the assertion using a credential record loaded entirely from your
database:

```go
var response webauthn.PublicKeyCredentialAssertion
if err := response.Parse(requestBody); err != nil {
	return err
}

pending, err := store.FindChallenge(response.GetChallenge(), webauthn.CeremonyAuthentication)
if err != nil {
	return err
}
credential, err := store.CredentialForUserID(pending.UserID)
if err != nil {
	return err
}

result, err := w.FinishLogin(
	&webauthn.LoginData{
		ClientDataJSON: response.ClientDataJSON,
		AuthData:       response.AuthenticatorData,
		Signature:      response.Signature,
		UserHandle:     response.UserHandle,
		CredentialID:   response.ID,
		StoredCredential: webauthn.StoredCredential{
			ID:         credential.ID,
			PublicKey:  credential.PublicKey,
			SignCount:  credential.SignCount,
			UserHandle: credential.UserHandle,
		},
	},
	pending.Challenge,
	func(challenge string, ceremony webauthn.CeremonyType, credentialID string, oldCount, newCount uint32) error {
		// Atomically consume the challenge and update the counter only if it still equals oldCount.
		return store.CommitLogin(challenge, ceremony, credentialID, oldCount, newCount)
	},
)
if err != nil {
	return err // Do not create an application session.
}

log.Printf("login accepted; user verified: %t", result.UserVerified)
```

Only after `FinishLogin` succeeds should your application create its normal authenticated cookie or session.

### Why are the callbacks atomic?

Imagine that registration deletes the one-time challenge and the database crashes before saving the credential. The user
cannot retry because the challenge is already gone. Conversely, saving a credential without consuming its challenge can
allow the same response to be processed again. A single transaction guarantees that either both changes happen or
neither happens.

### Exact callback contract

Please refer to the [example](./example) folder for a complete example (with SQLite3 support) of how to use the library.
The key methods are BeginRegistration, FinishRegistration, BeginLogin, and FinishLogin. You must provide the trusted
ceremony state and transactional persistence callbacks used by the finish methods.

The finish methods require the challenge previously returned by the matching begin method and retrieved from the
trusted server-side ceremony state. `FinishRegistration` requires a `RegistrationStateConsumer` that atomically consumes
the exact, unexpired registration challenge and persists the verified credential while rejecting duplicate credential
IDs.
`FinishLogin` requires a `LoginStateConsumer` that atomically consumes the exact, unexpired authentication challenge and
compare-and-swaps the signature counter:
`FinishRegistration(registrationData, storedChallenge, commitRegistrationState)` and
`FinishLogin(loginData, storedChallenge, commitLoginState)`.

`LoginData.StoredCredential` must contain the credential ID, public key, signature counter, and owning user handle
loaded
from one trusted database record. The verifier rejects a response credential ID or user handle that does not match it.

> [!IMPORTANT]
> This is a breaking API requirement: completion calls without a trusted ceremony state and the appropriate atomic
> consumer are deliberately rejected. `RegistrationStateConsumer` replaces the former `ChallengeConsumer`; registration
> callbacks must now persist the verified credential and consume its challenge in one transaction.

### Key Caller Responsibilities:

* **User Management:** Maintain your user database.
* **Credential Storage:** The `RegistrationStateConsumer` must securely store the verified `CredentialID`, `PublicKey`,
  and `SignCount` for the owning user while consuming the challenge in the same transaction. Load that record together
  with its owning user handle into `LoginData.StoredCredential` for authentication.
* **Challenge Storage and Consumption:** Securely store each challenge in a trusted, server-side ceremony state, bind it
  to
  the user/session and intended ceremony, give it server-enforced expiry, then pass it to `FinishRegistration` or
  `FinishLogin`. Consumers must reject expired, reused, or wrong-ceremony challenges.
* **Atomic Registration State:** The `RegistrationStateConsumer` must persist the verified credential and consume its
  registration challenge in one transaction. A duplicate credential ID or write failure must roll back challenge
  consumption.
* **Atomic Login State:** The `LoginStateConsumer` must consume the authentication challenge and compare-and-swap the
  signature counter in one transaction. A counter conflict must roll back challenge consumption.

## AAGUID Lookup subpackage

The library includes a subpackage for AAGUID lookup. You are welcome to use it in your own projects. Go to
[example_aaguid](./example_aaguid) for more.

```go
package main

import (
	"fmt"
	"github.com/MrBoombastic/WebAuthn2Go/aaguid"
	"github.com/google/uuid"
)

func main() {
	fmt.Println(aaguid.LookupAuthenticatorUUID(uuid.MustParse("ed042a3a-4b22-4455-bb69-a267b652ae7e")))
	// Security Key NFC - Enterprise Edition (USB-A, USB-C) (Black) FW 5.7
}
```

## Dependencies

* `github.com/google/uuid` additional library used for AAGUID subpackage
* `github.com/go-webauthn/webauthn/protocol/webauthncbor` for CBOR decoding.
* `github.com/go-webauthn/webauthn/protocol/webauthncose` for parsing COSE public keys.

That may sound weird, that alternative to go-webauthn/webauthn uses that library, but actually there is no other choice
if you want to support more than just ES256 algorithm. I'm also assuming that outsourcing "the hard stuff" to more
popular libraries is a safer choice.

## Security Considerations

* **Challenge Management:** Finish methods require the expected server-side challenge and reject mismatches. Typed
  consumers run only after protocol validation and must enforce ceremony type, expiry, and one-time use.
* **Credential Binding:** Authentication verifies the response credential ID and optional user handle against one
  trusted
  `StoredCredential`; discoverable flows must set `RequireUserHandle`.
* **Credential Storage:** Registration succeeds only after the `RegistrationStateConsumer` atomically stores the
  credential together with challenge consumption. Authentication succeeds only after the `LoginStateConsumer`
  atomically advances the matching credential's counter together with challenge consumption.
* **Origin/RP ID Configuration:** `RPOrigins` must be exact HTTPS origins with no path, query, fragment, or user info
  (`http://localhost` is the sole HTTP exception). `RPID` must be a valid registrable domain (or localhost/IP) that
  matches every configured origin.
* **Attestation Verification:** This library currently **does not** perform cryptographic verification of attestation
  statements for `indirect` or `packed` formats.
  It only parses the authenticator data.
  If you require stricter
  verification of authenticator provenance, you would need to implement the specific verification logic for those
  formats.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## License

This project is licensed under the MIT License – see the LICENSE file for details.
