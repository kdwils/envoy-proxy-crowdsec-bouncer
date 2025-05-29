package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/kdwils/envoy-gateway-bouncer/bouncer"
	"github.com/kdwils/envoy-gateway-bouncer/cache"
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
		required := []string{
			"bouncer.apiKey",
			"bouncer.apiURL",
		}

		var missingKeys []string
		for _, key := range required {
			if !viper.IsSet(key) || viper.GetString(key) == "" {
				missingKeys = append(missingKeys, key)
			}
		}
		if len(missingKeys) > 0 {
			return fmt.Errorf("missing required configurations: %s", strings.Join(missingKeys, ", "))
		}

		config, err := config.New(v)
		if err != nil {
			return err
		}

		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.Level(config.Server.LogLevel)})
		logger := slog.New(handler)

		cache := cache.New(config.Cache.Ttl, config.Cache.MaxEntries)
		go cache.Cleanup()

		bouncer, err := bouncer.NewEnvoyBouncer(config.Bouncer.ApiKey, config.Bouncer.ApiURL, config.Bouncer.TrustedProxies, cache)
		if err != nil {
			return err
		}
		go bouncer.Sync(context.Background())

		server := server.NewServer(config, bouncer, logger)
		err = server.Serve(config.Server.Port)
		return err
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
