package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kdwils/envoy-proxy-bouncer/bouncer"
	"github.com/kdwils/envoy-proxy-bouncer/config"
	"github.com/kdwils/envoy-proxy-bouncer/logger"
	"github.com/kdwils/envoy-proxy-bouncer/server"
	"github.com/kdwils/envoy-proxy-bouncer/template"
	"github.com/kdwils/envoy-proxy-bouncer/version"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ServeCmd represents the serve command
var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "serve the envoy gateway bouncer",
	Long:  `serve the envoy gateway bouncer`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v := viper.GetViper()
		config, err := config.New(v)
		if err != nil {
			return err
		}

		level := logger.LevelFromString(config.Server.LogLevel)

		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		slogger := slog.New(handler)
		slogger.Info("starting envoy-proxy-bouncer", "version", version.Version, "logLevel", level)

		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		ctx = logger.WithContext(ctx, slogger)

		bouncer, err := bouncer.New(config)
		if err != nil {
			return err
		}
		go bouncer.Sync(ctx)

		if config.Bouncer.Enabled && config.Bouncer.Metrics {
			slogger.Info("metrics enabled, starting bouncer metrics")
			go func() {
				if err := bouncer.Metrics(ctx); err != nil {
					slogger.Error("metrics error", "error", err)
				}
			}()
		}

		templateStore, err := template.NewStore(template.Config{
			DeniedTemplatePath:  config.Templates.DeniedTemplatePath,
			CaptchaTemplatePath: config.Templates.CaptchaTemplatePath,
		})
		if err != nil {
			slogger.Error("failed to create template store", "error", err)
			templateStore = nil
		}

		server := server.NewServer(config, bouncer, bouncer.CaptchaService, templateStore, slogger)

		sigCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			slogger.Info("received signal", "signal", sig)
			cancel()
		}()

		err = server.ServeDual(sigCtx)
		if err == context.Canceled {
			slogger.Info("server shutdown complete")
			return nil
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(ServeCmd)
}
