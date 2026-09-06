package captcha

import "context"

// NoopCaptchaService is a CaptchaService that never challenges anyone and
// starts no background cleanup, used when the captcha component is disabled
// so callers don't need to nil-check it.
type NoopCaptchaService struct{}

func NewNoopCaptchaService() *NoopCaptchaService {
	return &NoopCaptchaService{}
}

func (n *NoopCaptchaService) IsEnabled() bool {
	return false
}

func (n *NoopCaptchaService) RequiresCaptcha(sessionToken string) bool {
	return false
}

func (n *NoopCaptchaService) CreateSession(ip, originalURL, sessionToken string) (*CaptchaSession, error) {
	return nil, nil
}

func (n *NoopCaptchaService) GetSession(challengeToken string) (*CaptchaSession, bool) {
	return nil, false
}

func (n *NoopCaptchaService) VerifyResponse(ctx context.Context, ip, challengeToken, challengeResponse string) (*VerificationResult, error) {
	return nil, nil
}

func (n *NoopCaptchaService) CookieName() string {
	return ""
}

func (n *NoopCaptchaService) StartCleanup(ctx context.Context) {}
