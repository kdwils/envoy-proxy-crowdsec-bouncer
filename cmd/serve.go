package cmd

import (
	"github.com/kdwils/envoy-gateway-bouncer/bouncer"
	"github.com/kdwils/envoy-gateway-bouncer/config"
	"github.com/kdwils/envoy-gateway-bouncer/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "serve the envoy gateway bouncer",
	Long:  `serve the envoy gateway bouncer`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v := viper.GetViper()
		config, err := config.New(v)
		if err != nil {
			return err
		}

		bouncer, err := bouncer.NewEnvoyBouncer(config.Bouncer.ApiKey, config.Bouncer.ApiURL, config.Bouncer.TrustedProxies)
		if err != nil {
			return err
		}

		server := server.NewServer(config, bouncer)
		err = server.Serve(config.Server.Port)
		return err
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
