package jwt_test

import (
	"bytes"
	stdjson "encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
	"github.com/stretchr/testify/require"
)

func TestClaimsNestedAccess(t *testing.T) {
	t.Parallel()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.IssuerKey, "https://example.com"))
	require.NoError(t, tok.Set(jwt.SubjectKey, "alice"))
	require.NoError(t, tok.Set("custom", "value"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for k := range tok.Claims() {
			// Calls that acquire the token's lock from within the yield
			// closure must not deadlock — Claims() must release the lock
			// before yielding.
			_, _ = tok.Field(k)
			_ = tok.Has(k)
			require.NoError(t, tok.Set("mutated", k))
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Claims() iteration deadlocked on nested token access")
	}
}

const (
	tokenTime = 233431200
)

var zeroval reflect.Value
var expectedTokenTime = time.Unix(tokenTime, 0).UTC()

func TestHeader(t *testing.T) {
	t.Parallel()
	values := map[string]any{
		jwt.AudienceKey:   []string{"developers", "secops", "tac"},
		jwt.ExpirationKey: expectedTokenTime,
		jwt.IssuedAtKey:   expectedTokenTime,
		jwt.IssuerKey:     "http://www.example.com",
		jwt.JwtIDKey:      "e9bc097a-ce51-4036-9562-d2ade882db0d",
		jwt.NotBeforeKey:  expectedTokenTime,
		jwt.SubjectKey:    "unit test",
	}

	t.Run("Roundtrip", func(t *testing.T) {
		t.Parallel()
		h := jwt.New()
		for k, v := range values {
			require.NoError(t, h.Set(k, v), `h.Set should succeed for key %#v`, k)
			got, ok := h.Field(k)
			require.True(t, ok, `h.Field should succeed for key %#v`, k)
			if !reflect.DeepEqual(v, got) {
				t.Fatalf("Values do not match: (%v, %v)", v, got)
			}
		}
	})

	t.Run("RoundtripError", func(t *testing.T) {
		t.Parallel()
		type dummyStruct struct {
			dummy1 int
			dummy2 float64
		}
		dummy := &dummyStruct{1, 3.4}

		values := map[string]any{
			jwt.AudienceKey:   dummy,
			jwt.ExpirationKey: dummy,
			jwt.IssuedAtKey:   dummy,
			jwt.IssuerKey:     dummy,
			jwt.JwtIDKey:      dummy,
			jwt.NotBeforeKey:  dummy,
			jwt.SubjectKey:    dummy,
		}

		h := jwt.New()
		for k, v := range values {
			err := h.Set(k, v)
			if err == nil {
				t.Fatalf("Setting %s value should have failed", k)
			}
		}
		err := h.Set("default", dummy) // private params
		if err != nil {
			t.Fatalf("Setting %s value failed", "default")
		}
		for k := range values {
			_, ok := h.Field(k)
			require.False(t, ok, `Getting %s value should have failed`, k)
		}
		tmp, ok := h.Field("default")
		require.True(t, ok, `Getting %s value should have succeeded`, "default")
		_ = tmp
	})

	t.Run("GetError", func(t *testing.T) {
		t.Parallel()
		h := jwt.New()
		issuer, ok := h.Issuer()
		require.False(t, ok, `Issuer should not be set`)
		require.Empty(t, issuer, `Issuer should be empty`)
		jwtID, ok := h.JwtID()
		require.False(t, ok, `JwtID should not be set`)
		require.Empty(t, jwtID, `JwtID should be empty`)
	})
}

func TestTokenMarshal(t *testing.T) {
	t.Parallel()
	t1 := jwt.New()
	err := t1.Set(jwt.JwtIDKey, "AbCdEfG")
	if err != nil {
		t.Fatalf("Failed to set JWT ID: %s", err.Error())
	}
	err = t1.Set(jwt.SubjectKey, "foobar@example.com")
	if err != nil {
		t.Fatalf("Failed to set Subject: %s", err.Error())
	}

	// Silly fix to remove monotonic element from time.Time obtained
	// from time.Now(). Without this, the equality comparison goes
	// ga-ga for golang tip (1.9)
	now := time.Unix(time.Now().Unix(), 0)
	err = t1.Set(jwt.IssuedAtKey, now.Unix())
	if err != nil {
		t.Fatalf("Failed to set IssuedAt: %s", err.Error())
	}
	err = t1.Set(jwt.NotBeforeKey, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("Failed to set NotBefore: %s", err.Error())
	}
	err = t1.Set(jwt.ExpirationKey, now.Add(10*time.Second).Unix())
	if err != nil {
		t.Fatalf("Failed to set Expiration: %s", err.Error())
	}
	err = t1.Set(jwt.AudienceKey, []string{"devops", "secops", "tac"})
	if err != nil {
		t.Fatalf("Failed to set audience: %s", err.Error())
	}
	err = t1.Set("custom", "MyValue")
	if err != nil {
		t.Fatalf(`Failed to set private claim "custom": %s`, err.Error())
	}
	jsonbuf1, err := json.MarshalIndent(t1, "", "  ")
	if err != nil {
		t.Fatalf("JSON Marshal failed: %s", err.Error())
	}

	t2 := jwt.New()
	require.NoError(t, json.Unmarshal(jsonbuf1, t2), `json.Unmarshal should succeed`)
	require.Equal(t, t1, t2, "tokens should match")
	_, err = json.MarshalIndent(t2, "", "  ")
	require.NoError(t, err, `json.MarshalIndent should succeed`)
}

func TestToken(t *testing.T) {
	tok := jwt.New()

	def := map[string]struct {
		Value  any
		Method string
	}{
		jwt.AudienceKey: {
			Method: "Audience",
			Value:  []string{"developers", "secops", "tac"},
		},
		jwt.ExpirationKey: {
			Method: "Expiration",
			Value:  expectedTokenTime,
		},
		jwt.IssuedAtKey: {
			Method: "IssuedAt",
			Value:  expectedTokenTime,
		},
		jwt.IssuerKey: {
			Method: "Issuer",
			Value:  "http://www.example.com",
		},
		jwt.JwtIDKey: {
			Method: "JwtID",
			Value:  "e9bc097a-ce51-4036-9562-d2ade882db0d",
		},
		jwt.NotBeforeKey: {
			Method: "NotBefore",
			Value:  expectedTokenTime,
		},
		jwt.SubjectKey: {
			Method: "Subject",
			Value:  "unit test",
		},
		"myClaim": {
			Value: "hello, world",
		},
	}

	t.Run("Set", func(t *testing.T) {
		for k, kdef := range def {
			require.NoError(t, tok.Set(k, kdef.Value), `tok.Set(%s) should succeed`, k)
		}
	})
	t.Run("Field", func(t *testing.T) {
		rv := reflect.ValueOf(tok)
		for k, kdef := range def {
			getval, ok := tok.Field(k)
			require.True(t, ok, `tok.Field(%s) should succeed`, k)

			if mname := kdef.Method; mname != "" {
				method := rv.MethodByName(mname)
				require.NotEqual(t, zeroval, method, `method %s should not be zero value`, mname)
				retvals := method.Call(nil)
				require.Len(t, retvals, 2, `should have exactly one return value`)
				require.Equal(t, getval, retvals[0].Interface(), `values should match`)
			}
		}
	})
	t.Run("Roundtrip", func(t *testing.T) {
		buf, err := json.Marshal(tok)
		require.NoError(t, err, `json.Marshal should succeed`)
		newtok, err := jwt.ParseInsecure(buf)
		require.NoError(t, err, `jwt.Parse should succeed`)
		require.True(t, jwt.Equal(tok, newtok), `tokens should match`)
	})
	t.Run("Set/Remove", func(t *testing.T) {
		newtok, err := tok.Clone()
		require.NoError(t, err, `tok.Clone should succeed`)
		for _, k := range tok.Keys() {
			newtok.Remove(k)
		}

		require.Len(t, newtok.Keys(), 0, `toks should have 0 tok`)
		for _, k := range tok.Keys() {
			v, ok := tok.Field(k)
			require.True(t, ok, `tok.Field(%s) should succeed`, k)
			require.NoError(t, newtok.Set(k, v), `newtok.Set should succeed`)
		}
	})
}

func TestUnmarshalResetsPrivateClaims(t *testing.T) {
	t.Parallel()
	t.Run("direct UnmarshalJSON", func(t *testing.T) {
		t.Parallel()
		tok := jwt.New()
		require.NoError(t, json.Unmarshal([]byte(`{"role":"admin","sub":"x"}`), tok))
		v, ok := tok.Field("role")
		require.True(t, ok, `role claim should be present after first unmarshal`)
		require.Equal(t, "admin", v)

		// Reuse the same token instance for a payload that omits "role".
		require.NoError(t, json.Unmarshal([]byte(`{"sub":"y"}`), tok))
		_, ok = tok.Field("role")
		require.False(t, ok, `stale private claim "role" must be cleared on reuse`)
		sub, ok := tok.Subject()
		require.True(t, ok, `sub claim should be present after second unmarshal`)
		require.Equal(t, "y", sub)
	})
	t.Run("Parse with WithToken", func(t *testing.T) {
		t.Parallel()
		key := []byte("0123456789abcdef")

		t1 := jwt.New()
		require.NoError(t, t1.Set("role", "admin"))
		require.NoError(t, t1.Set(jwt.SubjectKey, "x"))
		signed1, err := jwt.Sign(t1, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jwt.Sign should succeed`)

		t2 := jwt.New()
		require.NoError(t, t2.Set(jwt.SubjectKey, "y"))
		signed2, err := jwt.Sign(t2, jwt.WithKey(jwa.HS256(), key))
		require.NoError(t, err, `jwt.Sign should succeed`)

		dst := jwt.New()
		_, err = jwt.Parse(signed1, jwt.WithKey(jwa.HS256(), key), jwt.WithToken(dst))
		require.NoError(t, err, `jwt.Parse should succeed`)
		v, ok := dst.Field("role")
		require.True(t, ok, `role claim should be present after first parse`)
		require.Equal(t, "admin", v)

		// Reuse the same destination token for a payload without "role".
		_, err = jwt.Parse(signed2, jwt.WithKey(jwa.HS256(), key), jwt.WithToken(dst))
		require.NoError(t, err, `jwt.Parse should succeed`)
		_, ok = dst.Field("role")
		require.False(t, ok, `stale private claim "role" must be cleared on reuse`)
		sub, ok := dst.Subject()
		require.True(t, ok, `sub claim should be present after second parse`)
		require.Equal(t, "y", sub)
	})
}

// A custom claim name must never be able to introduce members of its own.
// See GHSA-4cf7-xm37-g63h.
func TestClaimNameCannotInjectMembers(t *testing.T) {
	t.Parallel()

	const name = `x":0,"admin`

	tok, err := jwt.NewBuilder().Claim(name, true).Build()
	require.NoError(t, err, `jwt.NewBuilder should succeed`)

	buf, err := json.Marshal(tok)
	require.NoError(t, err, `json.Marshal should succeed`)

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf, &got), `serialized token should be valid JSON`)
	require.Len(t, got, 1, `exactly one claim should be serialized: %s`, buf)
	require.Contains(t, got, name, `claim name should round-trip unchanged: %s`, buf)

	// The injected member must not survive a sign/verify round trip either.
	key := []byte("0123456789abcdef0123456789abcdef")
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Sign should succeed`)

	parsed, err := jwt.Parse(signed, jwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err, `jwt.Parse should succeed`)

	_, ok := parsed.Field("admin")
	require.False(t, ok, `no "admin" claim should have been injected`)

	v, ok := parsed.Field(name)
	require.True(t, ok, `the original claim should be present`)
	require.Equal(t, true, v, `the original claim value should be preserved`)
}

func TestNumericDateTokenPrecision(t *testing.T) {
	oldParse, oldFormat, oldPedantic := types.ParsePrecision.Load(), types.FormatPrecision.Load(), types.Pedantic.Load()
	t.Cleanup(func() {
		types.ParsePrecision.Store(oldParse)
		types.FormatPrecision.Store(oldFormat)
		types.Pedantic.Store(oldPedantic)
	})
	require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePrecision(9)))
	key := bytes.Repeat([]byte{42}, 32)
	for _, oidc := range []bool{false, true} {
		for _, precision := range []int{0, 3, 9} {
			t.Run(fmt.Sprintf("openid=%v/precision=%d", oidc, precision), func(t *testing.T) {
				require.NoError(t, jwt.Settings(jwt.WithNumericDateFormatPrecision(precision)))
				tok := jwt.New()
				if oidc {
					tok = openid.New()
				}
				timestamp := time.Unix(2000000000, 123456789).UTC()
				for _, name := range []string{jwt.ExpirationKey, jwt.IssuedAtKey, jwt.NotBeforeKey} {
					require.NoError(t, tok.Set(name, timestamp))
				}
				raw, err := stdjson.Marshal(tok)
				require.NoError(t, err)
				var claims map[string]stdjson.RawMessage
				require.NoError(t, stdjson.Unmarshal(raw, &claims))
				want := map[int]string{0: "2000000000", 3: "2000000000.123", 9: "2000000000.123456789"}[precision]
				for _, name := range []string{jwt.ExpirationKey, jwt.IssuedAtKey, jwt.NotBeforeKey} {
					require.Equal(t, want, string(claims[name]))
				}
				wire, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
				require.NoError(t, err)
				payload, err := jws.Verify(wire, jws.WithKey(jwa.HS256(), key))
				require.NoError(t, err)
				require.JSONEq(t, string(raw), string(payload))
				target := jwt.New()
				if oidc {
					target = openid.New()
				}
				parsed, err := jwt.Parse(wire, jwt.WithKey(jwa.HS256(), key), jwt.WithToken(target), jwt.WithValidate(false))
				require.NoError(t, err)
				got, ok := parsed.IssuedAt()
				require.True(t, ok)
				expected := timestamp
				if precision == 0 {
					expected = timestamp.Truncate(time.Second)
				} else if precision == 3 {
					expected = timestamp.Truncate(time.Millisecond)
				}
				require.Equal(t, expected, got)
				other, err := tok.Clone()
				require.NoError(t, err)
				require.NoError(t, other.Set(jwt.IssuedAtKey, timestamp.Add(time.Millisecond)))
				require.Equal(t, precision == 0, jwt.Equal(tok, other))
			})
		}
	}
}

func TestNegativeFractionalNumericDate(t *testing.T) {
	oldParse, oldFormat, oldPedantic := types.ParsePrecision.Load(), types.FormatPrecision.Load(), types.Pedantic.Load()
	t.Cleanup(func() {
		types.ParsePrecision.Store(oldParse)
		types.FormatPrecision.Store(oldFormat)
		types.Pedantic.Store(oldPedantic)
	})
	for _, pedantic := range []bool{false, true} {
		for _, c := range []struct {
			number         string
			seconds, nanos int64
		}{
			{"-1.5", -2, 500000000}, {"-0.5", -1, 500000000}, {"-1.000000001", -2, 999999999},
			{"2000000000.123456789", 2000000000, 123456789}, {"-2208988800.000000001", -2208988801, 999999999}, {"10000000000.123456789", 10000000000, 123456789},
		} {
			t.Run(fmt.Sprintf("pedantic=%v/%s", pedantic, c.number), func(t *testing.T) {
				require.NoError(t, jwt.Settings(jwt.WithNumericDateParsePrecision(9), jwt.WithNumericDateFormatPrecision(9), jwt.WithNumericDateParsePedantic(pedantic)))
				tok, err := jwt.ParseInsecure([]byte(`{"iat":` + c.number + `}`))
				require.NoError(t, err)
				got, ok := tok.IssuedAt()
				require.True(t, ok)
				require.Equal(t, time.Unix(c.seconds, c.nanos).UTC(), got)
				raw, err := stdjson.Marshal(tok)
				require.NoError(t, err)
				again, err := jwt.ParseInsecure(raw)
				require.NoError(t, err)
				gotAgain, _ := again.IssuedAt()
				require.Equal(t, got, gotAgain)
			})
		}
	}
	require.NoError(t, jwt.Settings(jwt.WithNumericDateFormatPrecision(3)))
	for _, c := range []struct {
		time time.Time
		want string
	}{
		{time.Unix(-1, 999999999), "-0.000"}, {time.Unix(-1, 500000000), "-0.500"}, {time.Unix(-2, 0), "-2.000"}, {time.Unix(0, 1), "0.000"},
	} {
		require.Equal(t, c.want, (types.NumericDate{Time: c.time}).String())
	}
}
