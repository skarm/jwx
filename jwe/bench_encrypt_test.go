package jwe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// Header merging should not grow with the number of builtin key candidates
// supplied in one provider batch. Earlier candidates intentionally fail AEAD.
func BenchmarkDecryptKeyCandidates(b *testing.B) {
	key := bytes.Repeat([]byte{42}, 32)
	payload := []byte("candidate key attempts")
	wire, err := Encrypt(payload, WithKey(jwa.DIRECT(), key), WithContentEncryption(jwa.A256GCM()), WithJSON())
	if err != nil {
		b.Fatal(err)
	}
	for _, count := range []int{3, 20} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			keys := make([][]byte, count)
			for i := range count - 1 {
				keys[i] = bytes.Repeat([]byte{byte(i)}, 32)
			}
			keys[count-1] = key
			provider := KeyProviderFunc(func(_ context.Context, sink KeySink, _ Recipient, _ *Message) error {
				for _, candidate := range keys {
					sink.Key(jwa.DIRECT(), candidate)
				}
				return nil
			})
			b.ReportAllocs()
			for b.Loop() {
				got, err := Decrypt(wire, WithKeyProvider(provider))
				if err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(payload, got) {
					b.Fatal("unexpected plaintext")
				}
			}
		})
	}
}

func BenchmarkEncryptKey(b *testing.B) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		b.Fatal(err)
	}

	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	testcases := []struct {
		name string
		alg  jwa.KeyEncryptionAlgorithm
		enc  jwa.ContentEncryptionAlgorithm
		key  any
	}{
		{
			name: "RSA-OAEP",
			alg:  jwa.RSA_OAEP(),
			enc:  jwa.A256GCM(),
			key:  &rsaKey.PublicKey,
		},
		{
			name: "ECDH-ES",
			alg:  jwa.ECDH_ES(),
			enc:  jwa.A256GCM(),
			key:  &ecKey.PublicKey,
		},
		{
			name: "A256KW",
			alg:  jwa.A256KW(),
			enc:  jwa.A256GCM(),
			key:  symKey,
		},
		{
			name: "DIRECT",
			alg:  jwa.DIRECT(),
			enc:  jwa.A256GCM(),
			key:  symKey,
		},
	}

	for _, tc := range testcases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, err := Encrypt(payload,
					WithKey(tc.alg, tc.key),
					WithContentEncryption(tc.enc),
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecryptKey(b *testing.B) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		b.Fatal(err)
	}

	payload := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit")

	testcases := []struct {
		name   string
		alg    jwa.KeyEncryptionAlgorithm
		enc    jwa.ContentEncryptionAlgorithm
		encKey any
		decKey any
	}{
		{
			name:   "RSA-OAEP",
			alg:    jwa.RSA_OAEP(),
			enc:    jwa.A256GCM(),
			encKey: &rsaKey.PublicKey,
			decKey: rsaKey,
		},
		{
			name:   "ECDH-ES",
			alg:    jwa.ECDH_ES(),
			enc:    jwa.A256GCM(),
			encKey: &ecKey.PublicKey,
			decKey: ecKey,
		},
		{
			name:   "A256KW",
			alg:    jwa.A256KW(),
			enc:    jwa.A256GCM(),
			encKey: symKey,
			decKey: symKey,
		},
		{
			name:   "DIRECT",
			alg:    jwa.DIRECT(),
			enc:    jwa.A256GCM(),
			encKey: symKey,
			decKey: symKey,
		},
	}

	for _, tc := range testcases {
		b.Run(tc.name, func(b *testing.B) {
			encrypted, err := Encrypt(payload,
				WithKey(tc.alg, tc.encKey),
				WithContentEncryption(tc.enc),
			)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, err := Decrypt(encrypted, WithKey(tc.alg, tc.decKey))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
