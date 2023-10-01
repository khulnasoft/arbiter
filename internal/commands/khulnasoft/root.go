package khulnasoft

import (
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

func NewKhulnasoftRootCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:                   "khulnasoft",
		Short:                 "Commands for using arbiter with Khulnasoft",
		Aliases:               []string{"s"},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				logger.Fatal().Err(err).Msg("Failed to run khulnasoft command")
			}
		},
	}
	cmd.AddCommand(NewPackageCommand(logger))
	cmd.AddCommand(NewEnrichCommand(logger))

	return &cmd
}
