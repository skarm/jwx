package jwsbb

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// RequireKeySize enforces RFC 7518 sections 3.2, 3.3 and 3.5 for the
// built-in JOSE HMAC/RSA identifiers. Callers supply already-converted keys.
// Algorithms outside these identifiers keep their own key requirements.
func RequireKeySize(alg string, key any) error {
	var minimum int
	switch alg {
	case "HS256":
		minimum = 32
	case "HS384":
		minimum = 48
	case "HS512":
		minimum = 64
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		var pub *rsa.PublicKey
		switch k := key.(type) {
		case *rsa.PublicKey:
			pub = k
		case rsa.PublicKey:
			pub = &k
		case *rsa.PrivateKey:
			if k != nil {
				pub = &k.PublicKey
			}
		case rsa.PrivateKey:
			pub = &k.PublicKey
		case crypto.Signer:
			pub, _ = k.Public().(*rsa.PublicKey)
		}
		if pub == nil || pub.N == nil {
			return fmt.Errorf(`algorithm %q requires an RSA modulus of at least 2048 bits`, alg)
		}
		if bits := pub.N.BitLen(); bits < 2048 {
			return fmt.Errorf(`algorithm %q requires an RSA modulus of at least 2048 bits; got %d`, alg, bits)
		}
		return nil
	default:
		return nil
	}
	raw, ok := key.([]byte)
	if !ok {
		return fmt.Errorf(`algorithm %q requires a []byte HMAC key`, alg)
	}
	if len(raw) < minimum {
		return fmt.Errorf(`algorithm %q requires an HMAC key of at least %d bytes; got %d`, alg, minimum, len(raw))
	}
	return nil
}
