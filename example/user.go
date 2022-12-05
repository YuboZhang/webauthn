package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"

	"github.com/NHAS/webauthn/protocol"
	"github.com/NHAS/webauthn/webauthn"
)

// User represents the user model
type User struct {
	id          uint64
	name        string
	displayName string
	credentials map[string]*webauthn.Credential
}

func (u *User) MarshalJSON() ([]byte, error) {
	var anon = struct {
		Id          uint64
		Name        string
		DisplayName string
		Credentials map[string]webauthn.Credential
	}{
		Id:          u.id,
		Name:        u.name,
		DisplayName: u.displayName,
		Credentials: make(map[string]webauthn.Credential),
	}

	for id, cred := range u.credentials {
		anon.Credentials[id] = *cred
	}

	return json.Marshal(&anon)
}

// NewUser creates and returns a new User
func NewUser(name string, displayName string) *User {

	user := &User{}
	user.id = randomUint64()
	user.name = name
	user.displayName = displayName
	user.credentials = map[string]*webauthn.Credential{}

	return user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

// WebAuthnID returns the user's ID
func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.id))
	return buf
}

// WebAuthnName returns the user's username
func (u User) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name
func (u User) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.credentials[string(cred.ID)] = &cred
}

// WebAuthnCredentials returns credentials owned by the user
func (u User) WebAuthnCredential(ID []byte) (out *webauthn.Credential) {
	return u.credentials[string(ID)]
}

// WebAuthnCredentials returns credentials owned by the user
func (u User) WebAuthnCredentials() (out []*webauthn.Credential) {
	for _, cred := range u.credentials {
		out = append(out, cred)
	}

	return
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u User) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}
