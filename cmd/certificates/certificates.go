package certificates

import (
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/client"
	"github.com/spf13/cobra"
)

type Options struct {
}

func NewCertificatesCmd() *cobra.Command {
	certificatesCmd := &cobra.Command{
		Use:   "certificates",
		Short: "Management of certificates",
	}
	certificatesCmd.AddCommand(newCertificatesAddCmd())
	certificatesCmd.AddCommand(newCertificatesRenewCmd())
	return certificatesCmd
}

func newCertificatesAddCmd() *cobra.Command {
	var certificates []string
	backendUrl := ""
	var certificateListCmd = &cobra.Command{
		Use:   "add",
		Short: "Provision a new certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			err := c.AddCertificate(certificates)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := certificateListCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	certificateListCmd.MarkFlagRequired("backend-url")
	flags.StringArrayVarP(&certificates, "certificate", "c", []string{}, "")
	certificateListCmd.MarkFlagRequired("certificate")

	return certificateListCmd
}

func newCertificatesRenewCmd() *cobra.Command {
	var certificates string
	backendUrl := ""
	var certificateListCmd = &cobra.Command{
		Use:   "renew",
		Short: "Renew a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			err := c.RenewCertificate(certificates)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := certificateListCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	certificateListCmd.MarkFlagRequired("backend-url")
	flags.StringVarP(&certificates, "certificate", "c", "", "Certificate to renew")
	certificateListCmd.MarkFlagRequired("certificate")

	return certificateListCmd
}
