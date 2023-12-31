package khulnasoft

import (
	"fmt"

	"github.com/package-url/packageurl-go"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/khulnasoft/arbiter/lib/khulnasoft"
)

func NewPackageCommand(logger zerolog.Logger) *cobra.Command {
	cmd := cobra.Command{
		Use:   "package <purl>",
		Short: "Return package vulnerabilities from Khulnasoft",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			purl, err := packageurl.FromString(args[0])
			if err != nil {
				logger.Fatal().Err(err).Msg("Not a valid purl")
			}
			logger.Debug().Str("purl", args[0]).Msg("Looking up package vulnerabilities from Khulnasoft")
			resp, err := khulnasoft.GetPackageVulnerabilities(purl)
			if err != nil {
				logger.Fatal().Err(err).Msg("An error occurred")
			}
			fmt.Print(string(resp.Body))
		},
	}
	return &cmd
}
