package cmd

import (
	"fmt"

	"github.com/kdwils/envoy-proxy-bouncer/version"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "envoy-proxy-bouncer version",
	Long:  `envoy-proxy-bouncer version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
