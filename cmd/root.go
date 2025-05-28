/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "envoy-gateway-bouncer",
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
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("bouncer.apiKey", "")
	viper.SetDefault("bouncer.apiURL", "")
	viper.SetDefault("bouncer.headers", []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP"})

}
