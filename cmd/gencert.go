package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	debug bool

	rootCmd = &cobra.Command{
		Use:   "gencert",
		Short: "gencert is a simple utility to generate certificates for testing.",
	}
)

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "v", false, "Debug mode")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
