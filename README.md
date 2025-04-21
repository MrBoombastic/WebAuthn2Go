# WebAuthn2Go - Go WebAuthn Server Library

![docs/hero.png](docs/hero.png)

[![Go Reference](https://pkg.go.dev/badge/github.com/MrBoombastic/WebAuthn2Go.svg)](https://pkg.go.dev/github.com/MrBoombastic/WebAuthn2Go)

A Go library designed to simplify the server-side implementation of the WebAuthn (FIDO2) protocol for passwordless
authentication.

## Features

* **WebAuthn Server Logic:** Handles core server-side registration and authentication ceremonies.
* **Attestation Support:**
  * Accepts `"none"`, `"indirect"`, and `"packed"` attestation formats.
    * Currently, **skips cryptographic verification** of attestation statements (`AttStmt`), focusing on extracting
      authenticator data (`AuthData`) including AAGUID and Public Key.
* **Assertion Verification:** Validates login assertions including challenge, origin, RP ID, user presence/verification
  flags, and signature.
* **Sign Count Protection:** Checks for increasing sign counts to help prevent replay attacks (requires secure storage
  by the caller).
* **AAGUID Lookup:** Provides a utility to look up authenticator names based on AAGUID.
* **Configuration:** Simple configuration for Relying Party details.

## Why this library?

This library is designed to be easy to use and integrate into existing Go applications. You don't need to especially
implement custom interfaces or convert your Fiber's fasthttp.Request into http.Request, like
in https://github.com/go-webauthn/webauthn. There are no other alternatives, except
the https://github.com/egregors/passkey, which is a wrapper around the first one, which additionally can set cookies for
you.

If you want more flexibility or control, and you don't need fancy features - this is the library for You.

## Why NOT this library?

This library is not intended to be a full-fledged WebAuthn implementation. It does not handle attestation verification,
for example. This library is also in early development, so may be not suitable for production use yet.

The library is also not popular. It's possible that this repo has more or less zero stars and has never been reviewed or
used by the 3rd party. So, if you are looking for a battle-tested library, this is not the one.

One more thing - **the code is written with the partial help of AI**. Although the author tried his best to understand
WebAuthn
specification and read various sources, the code may be far from perfect or even insecure. Every line of code has been
read and verified by myself. It wasn't just *do webauthn lib wololo* in ChatGPT. But still, please use it at your own
risk.

Used sources:

- https://www.corbado.com/glossary/attestation and other glossary entries - easy readable
- https://webauthn.guide/ - general overview
- https://www.w3.org/TR/webauthn/ - THE specification

## Example

There is a simple example in the [example](./example) folder.
It uses the `github.com/gofiber/fiber/v2` web framework, but you can use whatever you want.

## Installation

```bash
go get github.com/MrBoombastic/WebAuthn2Go
```

## Configuration

Before using the library, you need to configure your Relying Party (RP) details and other minor settings.

```go
w, err := webauthn.New(&webauthn.Config{
    RPID:             "localhost",                       // Domain name only - must match the domain in your URL
    RPDisplayName:    "WebAuthn2Go Example",             // Display name
    RPOrigins:        []string{"https://yourdomain.com", "https://auth.yourdomain.com"}, // Allowed origins - with protocol and port
    Timeout:          300_000,                           // Milliseconds, 5 minutes
    UserVerification: webauthn.UVPreferred,              // User verification requirement
    Attestation:      webauthn.AttestationIndirect,      // Attestation preference, Indirect gives us AAGUID
    Debug:            true,                              // Enable debug logging
})

w, err := webauthn.New(rpConfig)
if err != nil {
  // Handle configuration error (e.g., missing RPID/Origins)
  log.Fatalf("Failed to initialize WebAuthn: %v", err)
}
```

> [!IMPORTANT]
> * `RPID` **must** be the effective domain of your web application. Browsers enforce this strictly.
> * `RPOrigins` **must** include all origins (scheme + host + port if non-default) from which WebAuthn requests will
    originate. Mismatched origins will cause browser errors.

## Usage Overview

The library provides functions to handle the two main WebAuthn ceremonies: Registration (`Create`) and Authentication (
`Get`).

Please refer to the [example](./example) folder for a complete example (with SQLite3 support) of how to use the library.
The key methods are BeginRegistration, FinishRegistration, BeginLogin, and FinishLogin. You will have to provide
required data and save returned data manually by yourself.

### Key Caller Responsibilities:

* **User Management:** Maintain your user database.
* **Credential Storage:** Securely store the `CredentialID`, `PublicKey`, `AAGUID`, and `SignCount` associated with each
  user after successful registration.
* **Challenge Storage:** Securely store the challenge used for registration and authentication.

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

* `github.com/google/uuid` additional library for AAGUID subpackage
* `github.com/go-webauthn/webauthn/protocol/webauthncbor` for CBOR decoding.
* `github.com/go-webauthn/webauthn/protocol/webauthncose` for parsing COSE public keys.

That may sound weird, that alternative to go-webauthn/webauthn uses that library, but actually there is no other choice
if you want to support more than just ES256 algorithm. I'm also assuming that outsourcing "the hard stuff" to more
popular libraries is a safer choice.

## Security Considerations

* **Challenge Management:** Ensure challenges are unique per operation, securely stored server-side (e.g., in
  authenticated sessions), and used only once.
* **Credential Storage:** Store public keys and especially sign counts securely. Compromise of the sign count storage
  negates replay protection.
* **Origin/RP ID Configuration:** Incorrect `RPID` or `RPOrigins` configuration will break functionality and is a
  security boundary.
* **Attestation Verification:** This library currently **does not** perform cryptographic verification of attestation
  statements for `"indirect"` or `"packed"` formats. It only parses the authenticator data. If you require stricter
  verification of authenticator provenance, you would need to implement the specific verification logic for those
  formats.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
