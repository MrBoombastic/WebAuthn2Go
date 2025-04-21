package main

import (
	"fmt"
	"github.com/MrBoombastic/WebAuthn2Go/aaguid"
	"github.com/google/uuid"
)

func main() {
	fmt.Println(aaguid.LookupAuthenticatorUUID(uuid.MustParse("ed042a3a-4b22-4455-bb69-a267b652ae7e")))

	s, _ := aaguid.ToUUIDString("ED042a3a4b224455bb69a267b652AE7E")
	fmt.Println(s)

	uu, _ := aaguid.ToUUID("ED042a3a4b224455bb69a267b652AE7E")
	fmt.Println(uu.Variant())
}
