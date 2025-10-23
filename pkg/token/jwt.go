package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type SessionClaims struct {
	IP          string    `json:"ip"`
	OriginalURL string    `json:"original_url"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Provider    string    `json:"provider"`
	SiteKey     string    `json:"site_key"`
	CSRFToken   string    `json:"csrf_token"`
}

type VerificationClaims struct {
	IP         string    `json:"ip"`
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type JWT struct {
	signingKey []byte
}

func NewJWT(signingKey string) *JWT {
	return &JWT{
		signingKey: []byte(signingKey),
	}
}

func (j *JWT) CreateToken(claims SessionClaims) (string, error) {
	return j.createToken(claims)
}

func (j *JWT) CreateVerificationToken(claims VerificationClaims) (string, error) {
	return j.createToken(claims)
}

func (j *JWT) createToken(claims any) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)

	message := headerEncoded + "." + claimsEncoded

	signature := j.sign(message)
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return message + "." + signatureEncoded, nil
}

func (j *JWT) VerifyToken(token string) (*SessionClaims, error) {
	var claims SessionClaims
	if err := j.verifyToken(token, &claims); err != nil {
		return nil, err
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

func (j *JWT) VerifyVerificationToken(token string) (*VerificationClaims, error) {
	var claims VerificationClaims
	if err := j.verifyToken(token, &claims); err != nil {
		return nil, err
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

func (j *JWT) verifyToken(token string, claims any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format")
	}

	headerEncoded := parts[0]
	claimsEncoded := parts[1]
	signatureEncoded := parts[2]

	message := headerEncoded + "." + claimsEncoded

	expectedSignature := j.sign(message)
	expectedSignatureEncoded := base64.RawURLEncoding.EncodeToString(expectedSignature)

	if !hmac.Equal([]byte(signatureEncoded), []byte(expectedSignatureEncoded)) {
		return fmt.Errorf("invalid signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsEncoded)
	if err != nil {
		return fmt.Errorf("failed to decode claims: %w", err)
	}

	if err := json.Unmarshal(claimsJSON, claims); err != nil {
		return fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return nil
}

func (j *JWT) sign(message string) []byte {
	h := hmac.New(sha256.New, j.signingKey)
	h.Write([]byte(message))
	return h.Sum(nil)
}
