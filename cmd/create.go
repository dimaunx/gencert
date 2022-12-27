package cmd

import (
	"fmt"
	"github.com/dimaunx/gencert/pkg/cert"
	"github.com/dimaunx/gencert/pkg/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
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
			if err := utils.CreateDir(path); err != nil {
				return err
			}

			var certs []*cert.GenCertOutput
			root, err := cert.GenRootCA(caCn, path, caDays)
			if err != nil {
				return err
			}
			certs = append(certs, root)

			for i := 0; i < numIntermediates; i++ {
				// Auto generate names for the intermediate certificates.
				cn := fmt.Sprintf("%s-int0%d", caCn, i+1)

				switch intermediatesHierarchy {
				case "forest":
					// Sign all intermediate certificates with the root CA.
					out, err := cert.GenIntermediateCA(root.Certificate, root.PrivateKey, cn, path, intermediateDays)
					if err != nil {
						return err
					}
					certs = append(certs, out)
				case "ladder":
					if i == 0 {
						// If the intermediate is the first one in the chain sign it with the root CA.
						out, err := cert.GenIntermediateCA(root.Certificate, root.PrivateKey, cn, path, intermediateDays)
						if err != nil {
							return err
						}
						certs = append(certs, out)
					} else {
						// If the intermediate is not the first one in the chain sign it with the previous one.
						out, err := cert.GenIntermediateCA(certs[i].Certificate, certs[i].PrivateKey, cn, path, intermediateDays)
						if err != nil {
							return err
						}
						certs = append(certs, out)
					}
				default:
					return errors.Errorf("unsupported intermediate hierarchy type: %s", intermediatesHierarchy)
				}
			}

			// Sign the leaf client/server certificate with last certificate in the chain.
			last := certs[len(certs)-1]
			if err = cert.GenServerCert(last.Certificate, last.PrivateKey, certCn, path, certDays); err != nil {
				return err
			}

			// Export the CA chain to a file. Chain will contain root and all the intermediate certificates only.
			if err = cert.ExportPemChain(certs, path, "ca-chain.cert"); err != nil {
				return err
			}
			return nil
		},
	}
)
