package template

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

//go:embed html/denied.html
var defaultDeniedTemplate string

//go:embed html/captcha.html
var defaultCaptchaTemplate string

type Store struct {
	deniedTemplate  *template.Template
	captchaTemplate *template.Template
}

type Config struct {
	DeniedTemplatePath  string
	CaptchaTemplatePath string
}

func NewStore(cfg Config) (*Store, error) {

	deniedTemplate, err := loadTemplate("denied", defaultDeniedTemplate, cfg.DeniedTemplatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load denied template: %w", err)
	}

	captchaTemplate, err := loadTemplate("captcha", defaultCaptchaTemplate, cfg.CaptchaTemplatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load captcha template: %w", err)
	}

	return &Store{
		deniedTemplate:  deniedTemplate,
		captchaTemplate: captchaTemplate,
	}, nil
}

func loadTemplate(name, defaultContent, customPath string) (*template.Template, error) {
	content := defaultContent
	if customPath == "" {
		return template.New(name).Parse(content)
	}

	customContent, err := os.ReadFile(customPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read custom template %s: %w", customPath, err)
		}
		return template.New(name).Parse(content)
	}

	content = string(customContent)
	return template.New(name).Parse(content)
}

type DeniedTemplateData struct {
	IP        string
	Reason    string
	Action    string
	Timestamp time.Time
	Request   DeniedRequest
	Decision  *models.Decision
}

type DeniedRequest struct {
	Method   string
	Path     string
	Host     string
	Scheme   string
	Protocol string
	URL      string
}

func (s *Store) RenderDenied(data DeniedTemplateData) (string, error) {
	return s.renderTemplate(s.deniedTemplate, data)
}

type CaptchaTemplateData struct {
	Provider    string
	SiteKey     string
	CallbackURL string
	RedirectURL string
	SessionID   string
}

func (s *Store) RenderCaptcha(data CaptchaTemplateData) (string, error) {
	return s.renderTemplate(s.captchaTemplate, data)
}

func (s *Store) renderTemplate(tmpl *template.Template, data any) (string, error) {
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return buf.String(), nil
}
