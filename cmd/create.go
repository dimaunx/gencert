package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/dimaunx/gencert/pkg/cert"
	"github.com/dimaunx/gencert/pkg/utils"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.Flags().StringVar(&path, "path", "ca01", "Local directory for certificates creation.")
	createCmd.Flags().StringVar(&caCn, "ca-cn", "ca01", "CA certificate common name.")
	createCmd.Flags().IntVar(&caDays, "ca-days", 365, "CA certificate duration in days.")
	createCmd.Flags().BoolVar(&enableIntermediate, "int", true, "Whether to create an intermediate certificate or not.")
	createCmd.Flags().IntVar(&numIntermediates, "int-num", 1, "The number of intermediate certificates to create.")
	createCmd.Flags().IntVar(&intermediateDays, "int-days", 364, "Intermediate certificates duration in days.")
	createCmd.Flags().StringVar(&intermediatesHierarchy, "int-hierarchy", "forest", "Hierarchy of the intermediate certificates. 'forest' means all signed by the same root CA, 'ladder' means each intermediate is signed by a previous one.")
	createCmd.Flags().StringVar(&certCn, "cert-cn", "test.example.com", "Client/Server leaf certificate common name.")
	createCmd.Flags().IntVar(&certDays, "cert-days", 363, "Client/Server leaf certificate duration in days.")
}

var (
	path                   string
	caCn                   string
	caDays                 int
	certCn                 string
	certDays               int
	enableIntermediate     bool
	numIntermediates       int
	intermediatesHierarchy string
	intermediateDays       int

	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Generate CA/Intermediate and leaf certificates",
		Long:  `Generate CA/Intermediate and leaf certificates`,
		RunE: func(cmd *cobra.Command, args []string) error {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)

			if debug {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			}
			zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
			logger := zerolog.New(os.Stdout).With().Stack().Timestamp().Logger()

			if err := utils.CreateDir(path); err != nil {
				logger.Error().Err(err).Msgf("failed to create a local directory %s", path)
				return err
			}
			logger.Debug().Msgf("Successfully created local directory %s", path)

			var certs []*cert.GenCertOutput
			root, err := cert.GenCert(&cert.GenCertInput{
				Type:         "root",
				CommonName:   caCn,
				Dir:          path,
				DaysDuration: caDays,
			})
			if err != nil {
				logger.Error().Err(err).Msg("failed to generate root CA")
				return err
			}
			certs = append(certs, root)
			logger.Debug().Msgf("Successfully generated a root CA cn: %s location: %s", caCn, root.FileName)

			for i := 0; i < numIntermediates; i++ {
				// Auto generate names for the intermediate certificates.
				cn := fmt.Sprintf("%s-int0%d", caCn, i+1)

				switch intermediatesHierarchy {
				case "forest":
					// Sign all intermediate certificates with the root CA.
					out, err := cert.GenCert(&cert.GenCertInput{
						Type:             "intermediate",
						CommonName:       cn,
						Dir:              path,
						DaysDuration:     intermediateDays,
						IssuerCert:       root.Certificate,
						IssuerPrivateKey: root.PrivateKey,
					})
					if err != nil {
						logger.Error().Err(err).Msgf("failed to generate an intermediate CA cn: %s", cn)
						return err
					}
					certs = append(certs, out)
					logger.Debug().Msgf("Successfully generated an intermediate CA cn: %s location: %s", cn, out.FileName)
				case "ladder":
					// Sign the first intermediate with the root CA.
					input := &cert.GenCertInput{
						Type:             "intermediate",
						CommonName:       cn,
						Dir:              path,
						DaysDuration:     intermediateDays,
						IssuerCert:       root.Certificate,
						IssuerPrivateKey: root.PrivateKey,
					}

					if i != 0 {
						// If the intermediate is not the first one in the chain sign it with the previous one.
						input.IssuerCert = certs[i].Certificate
						input.IssuerPrivateKey = certs[i].PrivateKey
					}

					out, err := cert.GenCert(input)
					if err != nil {
						logger.Error().Err(err).Msgf("failed to generate an intermediate CA cn: %s", cn)
						return err
					}
					certs = append(certs, out)
					logger.Debug().Msgf("Successfully generated an intermediate CA cn: %s location: %s", cn, out.FileName)
				default:
					return errors.Errorf("unsupported intermediate hierarchy type: %s", intermediatesHierarchy)
				}
			}

			// Sign the leaf client/server certificate with last certificate in the chain.
			last := certs[len(certs)-1]
			out, err := cert.GenCert(&cert.GenCertInput{
				Type:             "leaf",
				CommonName:       certCn,
				Dir:              path,
				DaysDuration:     certDays,
				IssuerCert:       last.Certificate,
				IssuerPrivateKey: last.PrivateKey,
			})
			if err != nil {
				logger.Error().Err(err).Msgf("failed to generate a client/server certificate cn: %s", certCn)
				return err
			}
			logger.Debug().Msgf("Successfully generated a client/server certificate cn: %s location: %s", certCn, out.FileName)

			// Export the CA chain to a file. The chain will contain root and all the intermediate certificates only.
			if err = cert.ExportPemChain(certs, path, "ca-chain.cert"); err != nil {
				logger.Error().Err(err).Msg("failed to to export the CA chain")
				return err
			}
			logger.Debug().Msgf("Successfully exported the CA chain to: %s", filepath.Join(path, "ca-chain.cert"))
			return nil
		},
	}
)
