package goverify

import (
	"crypto/rsa"
	"fmt"
)

// A Verifier can validate signatures that verify against a public key.
type Verifier interface {
	// Verify returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Verify(data []byte, sig []byte) error

	VerifyHash(hash []byte, sig []byte) error
}

func newVerifierFromKey(k interface{}) (Verifier, error) {
	var sshKey Verifier
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &RSAPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}
