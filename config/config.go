package config

import (
	"errors"

	"github.com/spf13/viper"
)

type Config struct {
	Server  Server  `yaml:"server" json:"server"`
	Bouncer Bouncer `yaml:"bouncer" json:"bouncer"`
}

type Server struct {
	Port     int    `yaml:"port" json:"port"`
	LogLevel string `yaml:"logLevel" json:"logLevel"`
}

type Bouncer struct {
	ApiKey         string   `yaml:"apiKey" json:"apiKey"`
	ApiURL         string   `yaml:"apiURL" json:"apiURL"`
	TrustedProxies []string `yaml:"trustedProxies" json:"trustedProxies"`
	Metrics        bool     `yaml:"metrics" json:"metrics"`
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
