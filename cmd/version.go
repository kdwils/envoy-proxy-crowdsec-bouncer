package cmd

import (
	"fmt"

	"github.com/kdwils/envoy-gateway-bouncer/version"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "envoy-gateway-bouncer version",
	Long:  `envoy-gateway-bouncer version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
