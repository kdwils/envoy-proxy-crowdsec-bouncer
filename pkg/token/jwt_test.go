package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJWT(t *testing.T) {
	signingKey := "test-signing-key"
	jwt := NewJWT(signingKey)

	require.NotNil(t, jwt)
	assert.Equal(t, []byte(signingKey), jwt.signingKey)
}

func TestJWT_CreateToken(t *testing.T) {
	t.Run("creates valid token with all claims", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")
		now := time.Now()
		expiresAt := now.Add(5 * time.Minute)

		claims := SessionClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com/test",
			CreatedAt:   now,
			ExpiresAt:   expiresAt,
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CSRFToken:   "test-csrf-token",
		}

		token, err := jwt.CreateToken(claims)

		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Contains(t, token, ".")
		parts := splitToken(token)
		assert.Len(t, parts, 3)
	})

	t.Run("creates different tokens for different claims", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")
		now := time.Now()

		claims1 := SessionClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com/test1",
			CreatedAt:   now,
			ExpiresAt:   now.Add(5 * time.Minute),
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CSRFToken:   "csrf-token-1",
		}

		claims2 := SessionClaims{
			IP:          "192.168.1.2",
			OriginalURL: "http://example.com/test2",
			CreatedAt:   now,
			ExpiresAt:   now.Add(5 * time.Minute),
			Provider:    "turnstile",
			SiteKey:     "test-site-key-2",
			CSRFToken:   "csrf-token-2",
		}

		token1, err := jwt.CreateToken(claims1)
		require.NoError(t, err)

		token2, err := jwt.CreateToken(claims2)
		require.NoError(t, err)

		assert.NotEqual(t, token1, token2)
	})
}

func TestJWT_VerifyToken(t *testing.T) {
	t.Run("verifies valid token successfully", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")
		now := time.Now()
		expiresAt := now.Add(5 * time.Minute)

		originalClaims := SessionClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com/test",
			CreatedAt:   now,
			ExpiresAt:   expiresAt,
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CSRFToken:   "test-csrf-token",
		}

		token, err := jwt.CreateToken(originalClaims)
		require.NoError(t, err)

		verifiedClaims, err := jwt.VerifyToken(token)

		require.NoError(t, err)
		require.NotNil(t, verifiedClaims)
		assert.Equal(t, originalClaims.IP, verifiedClaims.IP)
		assert.Equal(t, originalClaims.OriginalURL, verifiedClaims.OriginalURL)
		assert.Equal(t, originalClaims.Provider, verifiedClaims.Provider)
		assert.Equal(t, originalClaims.SiteKey, verifiedClaims.SiteKey)
		assert.Equal(t, originalClaims.CSRFToken, verifiedClaims.CSRFToken)
		assert.True(t, originalClaims.CreatedAt.Equal(verifiedClaims.CreatedAt))
		assert.True(t, originalClaims.ExpiresAt.Equal(verifiedClaims.ExpiresAt))
	})

	t.Run("rejects token with invalid signature", func(t *testing.T) {
		jwt1 := NewJWT("signing-key-1")
		jwt2 := NewJWT("signing-key-2")

		now := time.Now()
		claims := SessionClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com/test",
			CreatedAt:   now,
			ExpiresAt:   now.Add(5 * time.Minute),
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CSRFToken:   "test-csrf-token",
		}

		token, err := jwt1.CreateToken(claims)
		require.NoError(t, err)

		verifiedClaims, err := jwt2.VerifyToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")
		now := time.Now()
		expiresAt := now.Add(-5 * time.Minute)

		claims := SessionClaims{
			IP:          "192.168.1.1",
			OriginalURL: "http://example.com/test",
			CreatedAt:   now.Add(-10 * time.Minute),
			ExpiresAt:   expiresAt,
			Provider:    "recaptcha",
			SiteKey:     "test-site-key",
			CSRFToken:   "test-csrf-token",
		}

		token, err := jwt.CreateToken(claims)
		require.NoError(t, err)

		verifiedClaims, err := jwt.VerifyToken(token)

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects malformed token with wrong number of parts", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")

		verifiedClaims, err := jwt.VerifyToken("invalid.token")

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects token with invalid base64 encoding", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")

		verifiedClaims, err := jwt.VerifyToken("invalid!!!.claims!!!.signature!!!")

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects token with invalid JSON in claims", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")

		verifiedClaims, err := jwt.VerifyToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bm90X2pzb24.signature")

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})

	t.Run("rejects completely invalid token", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")

		verifiedClaims, err := jwt.VerifyToken("not-a-jwt-token")

		assert.Error(t, err)
		assert.Nil(t, verifiedClaims)
	})
}

func TestJWT_Sign(t *testing.T) {
	t.Run("produces consistent signatures", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")
		message := "test-message"

		sig1 := jwt.sign(message)
		sig2 := jwt.sign(message)

		assert.Equal(t, sig1, sig2)
	})

	t.Run("produces different signatures for different messages", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")

		sig1 := jwt.sign("message-1")
		sig2 := jwt.sign("message-2")

		assert.NotEqual(t, sig1, sig2)
	})

	t.Run("produces different signatures with different keys", func(t *testing.T) {
		jwt1 := NewJWT("key-1")
		jwt2 := NewJWT("key-2")
		message := "test-message"

		sig1 := jwt1.sign(message)
		sig2 := jwt2.sign(message)

		assert.NotEqual(t, sig1, sig2)
	})
}

func TestJWT_RoundTrip(t *testing.T) {
	t.Run("successfully round-trips token with various claim values", func(t *testing.T) {
		jwt := NewJWT("test-signing-key")
		now := time.Now()

		testCases := []struct {
			name   string
			claims SessionClaims
		}{
			{
				name: "standard claims",
				claims: SessionClaims{
					IP:          "192.168.1.1",
					OriginalURL: "http://example.com/test",
					CreatedAt:   now,
					ExpiresAt:   now.Add(5 * time.Minute),
					Provider:    "recaptcha",
					SiteKey:     "test-site-key",
					CSRFToken:   "test-csrf-token",
				},
			},
			{
				name: "IPv6 address",
				claims: SessionClaims{
					IP:          "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
					OriginalURL: "https://example.com/secure",
					CreatedAt:   now,
					ExpiresAt:   now.Add(10 * time.Minute),
					Provider:    "turnstile",
					SiteKey:     "another-site-key",
					CSRFToken:   "another-csrf-token",
				},
			},
			{
				name: "URL with query parameters",
				claims: SessionClaims{
					IP:          "10.0.0.1",
					OriginalURL: "http://example.com/path?param1=value1&param2=value2",
					CreatedAt:   now,
					ExpiresAt:   now.Add(15 * time.Minute),
					Provider:    "recaptcha",
					SiteKey:     "site-key-3",
					CSRFToken:   "csrf-token-3",
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				token, err := jwt.CreateToken(tc.claims)
				require.NoError(t, err)

				verifiedClaims, err := jwt.VerifyToken(token)
				require.NoError(t, err)
				require.NotNil(t, verifiedClaims)

				assert.Equal(t, tc.claims.IP, verifiedClaims.IP)
				assert.Equal(t, tc.claims.OriginalURL, verifiedClaims.OriginalURL)
				assert.Equal(t, tc.claims.Provider, verifiedClaims.Provider)
				assert.Equal(t, tc.claims.SiteKey, verifiedClaims.SiteKey)
				assert.Equal(t, tc.claims.CSRFToken, verifiedClaims.CSRFToken)
			})
		}
	})
}

func splitToken(token string) []string {
	var parts []string
	var current string
	for _, c := range token {
		if c == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
