package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func validateMasquePeer(s string) error {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return fmt.Errorf("MASQUE peer key is not PEM")
	}
	k, e := x509.ParsePKIXPublicKey(b.Bytes)
	if e != nil {
		return fmt.Errorf("invalid MASQUE peer public key")
	}
	p, ok := k.(*ecdsa.PublicKey)
	if !ok || p.Curve != elliptic.P256() {
		return fmt.Errorf("MASQUE peer key is not P-256")
	}
	return nil
}
