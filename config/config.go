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
	TrustedProxies []string `yaml:"trustedProxies" json:"trustedProxies"`
}

type Server struct {
	Port     int    `yaml:"port" json:"port"`
	LogLevel string `yaml:"logLevel" json:"logLevel"`
}

type Bouncer struct {
	Enabled        bool   `yaml:"enabled" json:"enabled"`
	Metrics        bool   `yaml:"metrics" json:"metrics"`
	TickerInterval string `yaml:"tickerInterval" json:"tickerInterval"`
	ApiKey         string `yaml:"apiKey" json:"apiKey"`
	LAPIURL        string `yaml:"LAPIURL" json:"LAPIURL"`
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
