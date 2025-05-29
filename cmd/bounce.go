package cmd

import (
	"log"

	"github.com/kdwils/envoy-gateway-bouncer/bouncer"
	"github.com/kdwils/envoy-gateway-bouncer/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var ip string

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

		bouncer, err := bouncer.NewEnvoyBouncer(config.Bouncer.ApiKey, config.Bouncer.ApiURL, config.Bouncer.TrustedProxies)
		if err != nil {
			return err
		}

		bounce, err := bouncer.Bounce(ip, nil)
		if err != nil {
			return err
		}
		if bounce {
			log.Println("not allowed")
			return nil
		}

		log.Println("allowed")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(bounceCmd)
	bounceCmd.Flags().StringVarP(&ip, "ip", "i", "", "ip address")
}
