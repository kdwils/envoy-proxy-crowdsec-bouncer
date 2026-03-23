package config

import (
	"errors"
	"time"

	"github.com/kdwils/envoy-proxy-bouncer/webhook"
	"github.com/spf13/viper"
)

type Config struct {
	Server         Server    `yaml:"server" json:"server"`
	Bouncer        Bouncer   `yaml:"bouncer" json:"bouncer"`
	WAF            WAF       `yaml:"waf" json:"waf"`
	Captcha        Captcha   `yaml:"captcha" json:"captcha"`
	Webhook        Webhook   `yaml:"webhook" json:"webhook"`
	TrustedProxies []string  `yaml:"trustedProxies" json:"trustedProxies"`
	Templates      Templates `yaml:"templates" json:"templates"`
}

type Server struct {
	GRPCPort int    `yaml:"grpcPort" json:"grpcPort"`
	HTTPPort int    `yaml:"httpPort" json:"httpPort"`
	LogLevel string `yaml:"logLevel" json:"logLevel"`
}

type Captcha struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	Provider          string        `yaml:"provider" json:"provider"`
	SiteKey           string        `yaml:"siteKey" json:"siteKey"`
	SecretKey         string        `yaml:"secretKey" json:"secretKey"`
	SigningKey        string        `yaml:"signingKey" json:"signingKey"`
	CallbackURL       string        `yaml:"callbackURL" json:"callbackURL"`
	CookieDomain      string        `yaml:"cookieDomain" json:"cookieDomain"`
	CookieName        string        `yaml:"cookieName" json:"cookieName"`
	SecureCookie      bool          `yaml:"secureCookie" json:"secureCookie"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	ChallengeDuration time.Duration `yaml:"challengeDuration" json:"challengeDuration"`
	SessionDuration   time.Duration `yaml:"sessionDuration" json:"sessionDuration"`
}

type BouncerTLS struct {
	Enabled            bool   `yaml:"enabled" json:"enabled"`
	CertPath           string `yaml:"certPath" json:"certPath"`
	KeyPath            string `yaml:"keyPath" json:"keyPath"`
	CAPath             string `yaml:"caPath" json:"caPath"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify" json:"insecureSkipVerify"`
}

type Bouncer struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	Metrics         bool          `yaml:"metrics" json:"metrics"`
	TickerInterval  string        `yaml:"tickerInterval" json:"tickerInterval"`
	MetricsInterval time.Duration `yaml:"metricsInterval" json:"metricsInterval"`
	ApiKey          string        `yaml:"apiKey" json:"apiKey"`
	LAPIURL         string        `yaml:"lapiUrl" json:"lapiUrl"`
	BanStatusCode   int           `yaml:"banStatusCode" json:"banStatusCode"`
	TLS             BouncerTLS    `yaml:"tls" json:"tls"`
}

func (b Bouncer) ValidateAuth() error {
	if b.ApiKey != "" && b.TLS.Enabled {
		return errors.New("cannot use both API key and certificate auth")
	}
	if b.ApiKey == "" && !b.TLS.Enabled {
		return errors.New("api key or certificate auth required")
	}
	if b.TLS.Enabled && (b.TLS.CertPath == "" || b.TLS.KeyPath == "") {
		return errors.New("certificate auth requires both certPath and keyPath")
	}
	return nil
}

type WAF struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	AppSecURL string `yaml:"appSecURL" json:"appSecURL"`
	ApiKey    string `yaml:"apiKey" json:"apiKey"`
}

type Webhook struct {
	Subscriptions []webhook.Subscription `yaml:"subscriptions" json:"subscriptions"`
	SigningKey    string                 `yaml:"signingKey" json:"signingKey"`
	Timeout       time.Duration          `yaml:"timeout" json:"timeout"`
	BufferSize    int                    `yaml:"bufferSize" json:"bufferSize"`
}

type Templates struct {
	DeniedTemplatePath     string `yaml:"deniedTemplatePath" json:"deniedTemplatePath"`
	DeniedTemplateHeaders  string `yaml:"deniedTemplateHeaders" json:"deniedTemplateHeaders"`
	ShowDeniedPage         bool   `yaml:"showDeniedPage" json:"showDeniedPage"`
	CaptchaTemplatePath    string `yaml:"captchaTemplatePath" json:"captchaTemplatePath"`
	CaptchaTemplateHeaders string `yaml:"captchaTemplateHeaders" json:"captchaTemplateHeaders"`
}

func New(v *viper.Viper) (Config, error) {
	c := Config{}
	if v == nil {
		return c, errors.New("viper not initialized")
	}
	if v.ConfigFileUsed() != "" {
		err := v.ReadInConfig()
		if err != nil {
			return c, err
		}
	}
	err := v.Unmarshal(&c)
	return c, err
}
