package config

import (
	"errors"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server         Server    `yaml:"server" json:"server"`
	Bouncer        Bouncer   `yaml:"bouncer" json:"bouncer"`
	WAF            WAF       `yaml:"waf" json:"waf"`
	Captcha        Captcha   `yaml:"captcha" json:"captcha"`
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
	CallbackURL       string        `yaml:"callbackURL" json:"callbackURL"`
	Timeout           time.Duration `yaml:"timeout" json:"timeout"`
	ChallengeDuration time.Duration `yaml:"challengeDuration" json:"challengeDuration"`
	SessionDuration   time.Duration `yaml:"sessionDuration" json:"sessionDuration"`
}

type Bouncer struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	Metrics         bool          `yaml:"metrics" json:"metrics"`
	TickerInterval  string        `yaml:"tickerInterval" json:"tickerInterval"`
	MetricsInterval time.Duration `yaml:"metricsInterval" json:"metricsInterval"`
	ApiKey          string        `yaml:"apiKey" json:"apiKey"`
	LAPIURL         string        `yaml:"lapiUrl" json:"lapiUrl"`
}

type WAF struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	AppSecURL string `yaml:"appSecURL" json:"appSecURL"`
	ApiKey    string `yaml:"apiKey" json:"apiKey"`
}

type Templates struct {
	DeniedTemplatePath     string `yaml:"deniedTemplatePath" json:"deniedTemplatePath"`
	DeniedTemplateHeaders  string `yaml:"deniedTemplateHeaders" json:"deniedTemplateHeaders"`
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
