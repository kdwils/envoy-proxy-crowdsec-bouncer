package cmd

import (
	"log/slog"
	"os"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/cache"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ips []string

// bounceCmd represents the bounce command
var bounceCmd = &cobra.Command{
	Use:   "bounce",
	Short: "Test if an IP should be bounced or not",
	Long:  `A command that can be used to test if an IP should be bounced or not`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v := viper.GetViper()
		config, err := config.New(v)
		if err != nil {
			return err
		}

		level := logger.LevelFromString(config.Server.LogLevel)

		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		logger := slog.New(handler)

		cache := cache.New(config.Cache.Ttl, config.Cache.MaxEntries)
		bouncer, err := bouncer.NewEnvoyBouncer(config.Bouncer.ApiKey, config.Bouncer.ApiURL, config.Bouncer.TrustedProxies, cache)
		if err != nil {
			return err
		}

		for _, ip := range ips {
			bounce, err := bouncer.Bounce(cmd.Context(), ip, nil)
			if err != nil {
				return err
			}
			if bounce {
				logger.Info("not allowed", "ip", ip)
				return nil
			}
			logger.Info("allowed", "ip", ip)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(bounceCmd)
	bounceCmd.Flags().StringSliceVarP(&ips, "ips", "i", []string{}, "ip addresses")
}
