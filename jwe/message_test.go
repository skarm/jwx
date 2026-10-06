package jwe_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// TestJWEJSONAADRoundTrip pins RFC 7516 §7.2.1 — the "aad" member of the JWE
// JSON Serialization is BASE64URL(JWE AAD): the external Additional
// Authenticated Data alone, base64url-encoded with no padding. It must NOT
// carry the "protected header '.' aad" concatenation (that form is only the
// AEAD input, per §5.1/§5.2 step 14), and it must not be base64-encoded a
// second time. Before the fix, MarshalJSON emitted
// base64std(protectedB64 + "." + base64url(aad)), so a message carrying an
// external aad did not survive Parse -> json.Marshal -> Parse: the aad was
// silently corrupted (the lenient decoder accepts the mangled value without
// error).
func TestJWEJSONAADRoundTrip(t *testing.T) {
	extAAD := []byte("external-aad")
	// RFC 7516 §7.2.1: aad member == BASE64URL(JWE AAD).
	wantAADMember := base64.RawURLEncoding.EncodeToString(extAAD)
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"enc":"A128GCM"}`))
	src := fmt.Sprintf(
		`{"protected":%q,"encrypted_key":"","iv":"aXZpdml2aXZpdml2","ciphertext":"Y3Q","tag":"dGFn","aad":%q}`,
		protected, wantAADMember,
	)

	msg, err := jwe.Parse([]byte(src))
	require.NoError(t, err, `jwe.Parse should succeed`)
	require.Equal(t, extAAD, msg.AuthenticatedData(), `parsed aad should be the external AAD`)

	buf, err := json.Marshal(msg)
	require.NoError(t, err, `json.Marshal should succeed`)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf, &got), `re-parse of serialized message should succeed`)
	var gotAAD string
	require.NoError(t, json.Unmarshal(got["aad"], &gotAAD), `aad member should be a JSON string`)
	require.Equal(t, wantAADMember, gotAAD,
		`serialized "aad" member must be BASE64URL(JWE AAD) per RFC 7516 §7.2.1`)

	// The message must survive a full Parse -> Marshal -> Parse cycle.
	msg2, err := jwe.Parse(buf)
	require.NoError(t, err, `re-parse of the serialized message should succeed`)
	require.Equal(t, extAAD, msg2.AuthenticatedData(),
		`external AAD must be preserved across a serialization round trip`)
}

func TestJWESharedUnprotectedHeadersRoundTrip(t *testing.T) {
	t.Run("RFC7516AppendixA5", func(t *testing.T) {
		// https://www.rfc-editor.org/rfc/rfc7516#appendix-A.5
		const source = `{
			"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
			"unprotected":{"jku":"https://server.example.com/keys.jwks"},
			"header":{"alg":"A128KW","kid":"7"},
			"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
			"iv":"AxY8DCtDaGlsbGljb3RoZQ",
			"ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
			"tag":"Mz-VPPyU4RlcuYv1IwIvzw"
		}`
		message, err := jwe.Parse([]byte(source))
		require.NoError(t, err)
		serialized, err := json.Marshal(message)
		require.NoError(t, err)
		require.JSONEq(t, source, string(serialized))
	})

	key := bytes.Repeat([]byte{1}, 32)
	payload := []byte("shared unprotected headers")
	encrypted, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), key), jwe.WithContentEncryption(jwa.A256GCM()), jwe.WithJSON())
	require.NoError(t, err)
	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encrypted, &members))
	members["unprotected"] = json.RawMessage(`{"kid":"shared-key","custom":"quotes: \" and slash: \\"}`)
	source, err := json.Marshal(members)
	require.NoError(t, err)
	message, err := jwe.Parse(source)
	require.NoError(t, err)
	serialized, err := json.Marshal(message)
	require.NoError(t, err)
	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(serialized, &got))
	require.JSONEq(t, string(members["unprotected"]), string(got["unprotected"]), "unprotected must remain a JSON object")
	for _, name := range []string{"protected", "ciphertext", "iv", "tag"} {
		require.Equal(t, members[name], got[name], "cryptographic member %s must be preserved", name)
	}
	reparsed, err := jwe.Parse(serialized)
	require.NoError(t, err)
	kid, ok := reparsed.UnprotectedHeaders().KeyID()
	require.True(t, ok)
	require.Equal(t, "shared-key", kid)
	decrypted, err := jwe.Decrypt(serialized, jwe.WithKey(jwa.DIRECT(), key))
	require.NoError(t, err)
	require.Equal(t, payload, decrypted)
}

func TestRecipient(t *testing.T) {
	t.Run("JSON Marshaling", func(t *testing.T) {
		const src = `{"header":{"foo":"bar"},"encrypted_key":"Zm9vYmFyYmF6"}`
		r1 := jwe.NewRecipient()

		require.NoError(t, json.Unmarshal([]byte(src), r1), `json.Unmarshal should succeed`)

		buf, err := json.Marshal(r1)
		require.NoError(t, err, `json.Marshal should succeed`)
		require.Equal(t, []byte(src), buf, `json representation should match`)
	})
}

// Ciphertext must be a string (possibly empty), while IV and tag must be
// present and non-empty. In particular, empty ciphertext must not allow an
// empty authentication tag to reach the AEAD verification code path.
func TestJWEJSONRejectsInvalidCryptoFields(t *testing.T) {
	// Minimal protected headers "{}" base64url-encoded = "e30".
	testcases := []struct {
		name string
		body string
	}{
		{"missing ciphertext", `{"protected":"e30","iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"null ciphertext", `{"protected":"e30","ciphertext":null,"iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"non-string ciphertext", `{"protected":"e30","ciphertext":42,"iv":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"empty ciphertext and tag", `{"protected":"e30","ciphertext":"","iv":"AAAA","tag":"","recipients":[{}]}`},
		{"missing iv", `{"protected":"e30","ciphertext":"AAAA","tag":"AAAA","recipients":[{}]}`},
		{"empty iv", `{"protected":"e30","ciphertext":"AAAA","iv":"","tag":"AAAA","recipients":[{}]}`},
		{"missing tag", `{"protected":"e30","ciphertext":"AAAA","iv":"AAAA","recipients":[{}]}`},
		{"empty tag", `{"protected":"e30","ciphertext":"AAAA","iv":"AAAA","tag":"","recipients":[{}]}`},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwe.Parse([]byte(tc.body))
			require.Error(t, err, `jwe.Parse should reject JWE JSON with invalid crypto fields`)
		})
	}
}

func unionJWE(t *testing.T, protected *string, shared, recipient map[string]any, general bool) []byte {
	t.Helper()
	prefix := ""
	obj := map[string]any{}
	if protected != nil {
		prefix = base64.RawURLEncoding.EncodeToString([]byte(*protected))
		obj["protected"] = prefix
	}
	block, err := aes.NewCipher(bytes.Repeat([]byte{42}, 16))
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	iv := bytes.Repeat([]byte{7}, 12)
	ct := aead.Seal(nil, iv, []byte("payload"), []byte(prefix))
	enc := base64.RawURLEncoding.EncodeToString
	obj["iv"], obj["ciphertext"], obj["tag"] = enc(iv), enc(ct[:len(ct)-16]), enc(ct[len(ct)-16:])
	if shared != nil {
		obj["unprotected"] = shared
	}
	if general {
		entry := map[string]any{}
		if recipient != nil {
			entry["header"] = recipient
		}
		obj["recipients"] = []any{entry}
	} else if recipient != nil {
		obj["header"] = recipient
	}
	wire, err := stdjson.Marshal(obj)
	require.NoError(t, err)
	return wire
}

func TestJWEJSONHeaderUnion(t *testing.T) {
	cases := []struct {
		name, protected   string
		absent            bool
		shared, recipient map[string]any
		wantError         string
	}{
		{name: "protected algorithms", protected: `{"alg":"dir","enc":"A128GCM"}`},
		{name: "shared alg", protected: `{"enc":"A128GCM"}`, shared: map[string]any{"alg": "dir", "kid": "test"}},
		{name: "recipient alg", protected: `{"enc":"A128GCM"}`, recipient: map[string]any{"alg": "dir", "kid": "test"}},
		{name: "shared enc", protected: `{"alg":"dir"}`, shared: map[string]any{"enc": "A128GCM"}},
		{name: "recipient enc", protected: `{"alg":"dir"}`, recipient: map[string]any{"enc": "A128GCM"}},
		{name: "omitted protected shared", absent: true, shared: map[string]any{"alg": "dir", "enc": "A128GCM", "kid": "test"}},
		{name: "omitted protected recipient", absent: true, recipient: map[string]any{"alg": "dir", "enc": "A128GCM", "kid": "test"}},
		{name: "shared crit", protected: `{"alg":"dir","enc":"A128GCM"}`, shared: map[string]any{"crit": []string{"x"}, "x": true}, wantError: "must be in the protected"},
		{name: "shared null crit", protected: `{"alg":"dir","enc":"A128GCM"}`, shared: map[string]any{"crit": nil}, wantError: "must not be null"},
		{name: "recipient null crit", protected: `{"alg":"dir","enc":"A128GCM"}`, recipient: map[string]any{"crit": nil}, wantError: "must not be null"},
		{name: "protected null crit", protected: `{"alg":"dir","enc":"A128GCM","crit":null}`, wantError: "must not be null"},
		{name: "recipient crit", protected: `{"alg":"dir","enc":"A128GCM"}`, recipient: map[string]any{"crit": []string{"x"}, "x": true}, wantError: "must be in the protected"},
		{name: "shared zip", protected: `{"alg":"dir","enc":"A128GCM"}`, shared: map[string]any{"zip": "DEF"}, wantError: "must be in the protected"},
		{name: "duplicate protected recipient kid", protected: `{"alg":"dir","enc":"A128GCM","kid":"test"}`, recipient: map[string]any{"kid": "other"}, wantError: "multiple JOSE"},
		{name: "duplicate equal alg", protected: `{"alg":"dir","enc":"A128GCM"}`, recipient: map[string]any{"alg": "dir"}, wantError: "multiple JOSE"},
		{name: "duplicate shared private field", protected: `{"alg":"dir","enc":"A128GCM"}`, shared: map[string]any{"x": true}, recipient: map[string]any{"x": true}, wantError: "multiple JOSE"},
		{name: "duplicate protected shared private field", protected: `{"alg":"dir","enc":"A128GCM","x":true}`, shared: map[string]any{"x": false}, wantError: "multiple JOSE"},
		{name: "wrong advertised alg", protected: `{"enc":"A128GCM"}`, shared: map[string]any{"alg": "A128KW"}, wantError: "algorithms do not match"},
	}
	for _, c := range cases {
		for _, general := range []bool{false, true} {
			name := c.name
			if general {
				name += "/general"
			}
			t.Run(name, func(t *testing.T) {
				var protected *string
				if !c.absent {
					protected = &c.protected
				}
				wire := unionJWE(t, protected, c.shared, c.recipient, general)
				key := bytes.Repeat([]byte{42}, 16)
				got, err := jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), key))
				if c.wantError != "" {
					require.ErrorContains(t, err, c.wantError)
					if c.wantError == "must not be null" {
						_, err = jwe.Parse(wire)
						require.ErrorContains(t, err, c.wantError)
						_, err = jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), key), jwe.WithCritValidation(false))
						require.ErrorContains(t, err, c.wantError, "disabled critical-value validation must not permit null")
					}
					return
				}
				require.NoError(t, err)
				require.Equal(t, []byte("payload"), got)
				if (c.shared != nil && c.shared["kid"] == "test") || (c.recipient != nil && c.recipient["kid"] == "test") {
					jk, err := jwk.Import[jwk.Key](key)
					require.NoError(t, err)
					require.NoError(t, jk.Set(jwk.KeyIDKey, "test"))
					set := jwk.NewSet()
					require.NoError(t, set.AddKey(jk))
					got, err = jwe.Decrypt(wire, jwe.WithKeySet(set))
					require.NoError(t, err)
					require.Equal(t, []byte("payload"), got)
				}
				msg, err := jwe.Parse(wire)
				require.NoError(t, err)
				serialized, err := stdjson.Marshal(msg)
				require.NoError(t, err)
				if c.absent {
					require.NotContains(t, string(serialized), `"protected"`)
				}
				got, err = jwe.Decrypt(serialized, jwe.WithKey(jwa.DIRECT(), key))
				require.NoError(t, err)
				require.Equal(t, []byte("payload"), got)
			})
		}
	}
	for _, secondEnc := range []string{"A128GCM", "A256GCM", ""} {
		t.Run("multiple recipients/"+secondEnc, func(t *testing.T) {
			protected := `{"alg":"dir"}`
			wire := unionJWE(t, &protected, nil, map[string]any{"enc": "A128GCM"}, true)
			var fields map[string]any
			require.NoError(t, stdjson.Unmarshal(wire, &fields))
			second := map[string]any{}
			if secondEnc != "" {
				second["enc"] = secondEnc
			}
			fields["recipients"] = append(fields["recipients"].([]any), map[string]any{"header": second})
			wire, err := stdjson.Marshal(fields)
			require.NoError(t, err)
			calls := 0
			provider := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, _ jwe.Recipient, _ *jwe.Message) error {
				calls++
				sink.Key(jwa.DIRECT(), bytes.Repeat([]byte{42}, 16))
				return nil
			})
			_, parseErr := jwe.Parse(wire)
			got, err := jwe.Decrypt(wire, jwe.WithKeyProvider(provider))
			if secondEnc != "A128GCM" {
				require.ErrorContains(t, parseErr, "same content encryption")
				require.ErrorContains(t, err, "same content encryption")
				require.Zero(t, calls, "inconsistent enc must fail before key selection")
				return
			}
			require.NoError(t, parseErr)
			require.NoError(t, err)
			require.Equal(t, []byte("payload"), got)
			require.Equal(t, 1, calls)
		})
	}
	t.Run("merge once per provider batch", func(t *testing.T) {
		protected := `{"enc":"A128GCM"}`
		wire := unionJWE(t, &protected, nil, map[string]any{"alg": "dir"}, false)
		copies := 0
		provider := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, r jwe.Recipient, _ *jwe.Message) error {
			require.NoError(t, r.SetHeaders(copyCountingJWEHeaders{Headers: r.Headers(), copies: &copies}))
			for _, value := range []byte{0, 1, 42} {
				sink.Key(jwa.DIRECT(), bytes.Repeat([]byte{value}, 16))
			}
			return nil
		})
		got, err := jwe.Decrypt(wire, jwe.WithKeyProvider(provider))
		require.NoError(t, err)
		require.Equal(t, []byte("payload"), got)
		require.Equal(t, 1, copies, "wrong candidate keys must not cause repeated header copies")
	})
	t.Run("custom decrypter mutations remain visible", func(t *testing.T) {
		protected := `{"enc":"A128GCM"}`
		wire := unionJWE(t, &protected, nil, map[string]any{"alg": "dir"}, false)
		provider := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, _ jwe.Recipient, _ *jwe.Message) error {
			sink.Key(jwa.DIRECT(), headerMutatingJWEDecrypter{})
			sink.Key(jwa.DIRECT(), bytes.Repeat([]byte{42}, 16))
			return nil
		})
		got, err := jwe.Decrypt(wire, jwe.WithKeyProvider(provider))
		require.ErrorIs(t, err, jwe.AlgorithmMismatchError{})
		require.Nil(t, got, "the following key must not use the stale dir union")
	})
	t.Run("later provider mutations remain visible", func(t *testing.T) {
		protected := `{"enc":"A128GCM"}`
		wire := unionJWE(t, &protected, nil, map[string]any{"alg": "dir"}, false)
		first := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, _ jwe.Recipient, _ *jwe.Message) error {
			sink.Key(jwa.DIRECT(), bytes.Repeat([]byte{0}, 16))
			return nil
		})
		second := jwe.KeyProviderFunc(func(_ context.Context, sink jwe.KeySink, r jwe.Recipient, _ *jwe.Message) error {
			if err := r.Headers().Set(jwe.AlgorithmKey, jwa.A128KW()); err != nil {
				return err
			}
			sink.Key(jwa.DIRECT(), bytes.Repeat([]byte{42}, 16))
			return nil
		})
		got, err := jwe.Decrypt(wire, jwe.WithKeyProvider(first), jwe.WithKeyProvider(second))
		require.ErrorIs(t, err, jwe.AlgorithmMismatchError{})
		require.Nil(t, got, "a later provider must not use the previous provider's cached union")
	})
}

type copyCountingJWEHeaders struct {
	jwe.Headers
	copies *int
}

func (h copyCountingJWEHeaders) Copy(dst jwe.Headers) error {
	*h.copies++
	return h.Headers.Copy(dst)
}

type headerMutatingJWEDecrypter struct{}

func (headerMutatingJWEDecrypter) DecryptKey(_ jwa.KeyEncryptionAlgorithm, _ []byte, r jwe.Recipient, _ *jwe.Message) ([]byte, error) {
	if err := r.Headers().Set(jwe.AlgorithmKey, jwa.A128KW()); err != nil {
		return nil, err
	}
	return nil, errors.New("custom decrypter changed recipient headers")
}

func TestParsedJWEHeaderMutation(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 16)
	compact, err := jwe.Encrypt([]byte("payload"), jwe.WithKey(jwa.DIRECT(), key), jwe.WithContentEncryption(jwa.A128GCM()))
	require.NoError(t, err)
	msg, err := jwe.Parse(compact)
	require.NoError(t, err)
	require.NoError(t, msg.Recipients()[0].Headers().Set("x-recipient", "retained"))
	wire, err := json.Marshal(msg)
	require.NoError(t, err)
	require.Contains(t, string(wire), `"x-recipient":"retained"`)
	got, err := jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), key))
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)

	recipient := msg.Recipients()[0]
	require.NoError(t, msg.Set(jwe.RecipientsKey, []jwe.Recipient{recipient, recipient}))
	wire, err = json.Marshal(msg)
	require.NoError(t, err)
	require.Equal(t, 2, bytes.Count(wire, []byte(`"x-recipient":"retained"`)))
	got, err = jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), key))
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)
	require.NoError(t, recipient.Headers().Set(jwe.AlgorithmKey, jwa.A128KW()))
	_, err = json.Marshal(msg)
	require.ErrorContains(t, err, "copied protected header")

	msg, err = jwe.Parse(unionJWE(t, nil, map[string]any{"alg": "dir", "enc": "A128GCM"}, nil, false))
	require.NoError(t, err)
	require.NoError(t, msg.ProtectedHeaders().Set("x-protected", true))
	wire, err = json.Marshal(msg)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(wire, &fields))
	require.Contains(t, fields, "protected", "mutating the empty protected object creates a present member")
	for _, name := range []string{jwe.KeyIDKey, "x-private"} {
		for _, remove := range []bool{false, true} {
			t.Run(fmt.Sprintf("protected %s/remove=%t", name, remove), func(t *testing.T) {
				headers := jwe.NewHeaders()
				require.NoError(t, headers.Set(name, "initial"))
				compact, err := jwe.Encrypt([]byte("payload"), jwe.WithKey(jwa.DIRECT(), key), jwe.WithContentEncryption(jwa.A128GCM()), jwe.WithProtectedHeaders(headers))
				require.NoError(t, err)
				msg, err := jwe.Parse(compact)
				require.NoError(t, err)
				if remove {
					require.NoError(t, msg.ProtectedHeaders().Remove(name))
				} else {
					require.NoError(t, msg.ProtectedHeaders().Set(name, "updated"))
				}
				// Changing protected AAD requires a new tag. Compute it with
				// the standard library, without modifying recipient headers.
				prefix, err := msg.ProtectedHeaders().Encode()
				require.NoError(t, err)
				block, err := aes.NewCipher(key)
				require.NoError(t, err)
				aead, err := cipher.NewGCM(block)
				require.NoError(t, err)
				ct := aead.Seal(nil, msg.InitializationVector(), []byte("payload"), prefix)
				require.NoError(t, msg.Set(jwe.CipherTextKey, ct[:len(ct)-aead.Overhead()]))
				require.NoError(t, msg.Set(jwe.TagKey, ct[len(ct)-aead.Overhead():]))
				wire, err := json.Marshal(msg)
				require.NoError(t, err)
				var fields map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(wire, &fields))
				require.NotContains(t, fields, "header", "original synthetic fields must not become wire recipient fields")
				reparsed, err := jwe.Parse(wire)
				require.NoError(t, err)
				value, exists := reparsed.ProtectedHeaders().Field(name)
				if remove {
					require.False(t, exists)
				} else {
					require.True(t, exists)
					require.Equal(t, "updated", value)
				}
				got, err := jwe.Decrypt(wire, jwe.WithKey(jwa.DIRECT(), key))
				require.NoError(t, err)
				require.Equal(t, []byte("payload"), got)
			})
		}
	}
}
