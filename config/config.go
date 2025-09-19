package config

import (
	"errors"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server         Server   `yaml:"server" json:"server"`
	Bouncer        Bouncer  `yaml:"bouncer" json:"bouncer"`
	WAF            WAF      `yaml:"waf" json:"waf"`
	Captcha        Captcha  `yaml:"captcha" json:"captcha"`
	TrustedProxies []string `yaml:"trustedProxies" json:"trustedProxies"`
}

type Server struct {
	GRPCPort int    `yaml:"grpcPort" json:"grpcPort"`
	HTTPPort int    `yaml:"httpPort" json:"httpPort"`
	LogLevel string `yaml:"logLevel" json:"logLevel"`
	// Deprecated: Use GRPCPort instead
	Port int `yaml:"port" json:"port"`
}

type Captcha struct {
	Enabled              bool          `yaml:"enabled" json:"enabled"`
	Provider             string        `yaml:"provider" json:"provider"`
	SiteKey              string        `yaml:"siteKey" json:"siteKey"`
	SecretKey            string        `yaml:"secretKey" json:"secretKey"`
	CacheDuration        time.Duration `yaml:"cacheDuration" json:"cacheDuration"`
	CallbackURL          string        `yaml:"callbackURL" json:"callbackURL"`
	Timeout              time.Duration `yaml:"timeout" json:"timeout"`
	CacheCleanupInterval time.Duration `yaml:"cacheCleanupInterval" json:"cacheCleanupInterval"`
}

type Bouncer struct {
	Enabled              bool          `yaml:"enabled" json:"enabled"`
	Metrics              bool          `yaml:"metrics" json:"metrics"`
	TickerInterval       string        `yaml:"tickerInterval" json:"tickerInterval"`
	MetricsInterval      time.Duration `yaml:"metricsInterval" json:"metricsInterval"`
	ApiKey               string        `yaml:"apiKey" json:"apiKey"`
	LAPIURL              string        `yaml:"LAPIURL" json:"LAPIURL"`
	CacheCleanupInterval time.Duration `yaml:"cacheCleanupInterval" json:"cacheCleanupInterval"`
}

type WAF struct {
	Enabled   bool          `yaml:"enabled" json:"enabled"`
	Timeout   time.Duration `yaml:"timeout" json:"timeout"`
	AppSecURL string        `yaml:"appSecURL" json:"appSecURL"`
	ApiKey    string        `yaml:"apiKey" json:"apiKey"`
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
