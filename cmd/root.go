package cmd

import (
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "envoy-proxy-bouncer",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (json or yaml)")
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("ENVOY_BOUNCER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", ""))
	viper.AutomaticEnv()

	viper.SetDefault("trustedProxies", []string{})

	viper.SetDefault("server.grpcPort", 8080)
	viper.SetDefault("server.httpPort", 8081)
	viper.SetDefault("server.logLevel", slog.LevelInfo)

	viper.SetDefault("bouncer.apiKey", "")
	viper.SetDefault("bouncer.lapiURL", "")
	viper.SetDefault("bouncer.enabled", true)
	viper.SetDefault("bouncer.metrics", false)
	viper.SetDefault("bouncer.tickerInterval", "10s")
	viper.SetDefault("bouncer.metricsInterval", "10m")
	viper.SetDefault("bouncer.banStatusCode", 403)

	viper.SetDefault("waf.enabled", false)
	viper.SetDefault("waf.apiKey", "")
	viper.SetDefault("waf.appSecURL", "")

	viper.SetDefault("captcha.enabled", false)
	viper.SetDefault("captcha.provider", "")
	viper.SetDefault("captcha.siteKey", "")
	viper.SetDefault("captcha.secretKey", "")
	viper.SetDefault("captcha.signingKey", "")
	viper.SetDefault("captcha.callbackURL", "")
	viper.SetDefault("captcha.cookieDomain", "")
	viper.SetDefault("captcha.cookieName", "session")
	viper.SetDefault("captcha.secureCookie", true)
	viper.SetDefault("captcha.timeout", "10s")
	viper.SetDefault("captcha.challengeDuration", "5m")
	viper.SetDefault("captcha.sessionDuration", "15m")

	viper.SetDefault("templates.deniedTemplatePath", "")
	viper.SetDefault("templates.deniedTemplateHeaders", "text/html; charset=utf-8")
	viper.SetDefault("templates.captchaTemplatePath", "")
	viper.SetDefault("templates.captchaTemplateHeaders", "text/html; charset=utf-8")
}
