package certificates

import (
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/client"
	"github.com/spf13/cobra"
	"io/ioutil"
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
	certificatesCmd.AddCommand(newCertificatesCustomAddCmd())
	certificatesCmd.AddCommand(newCertificatesCustomDeleteCmd())
	return certificatesCmd
}

func newCertificatesCustomDeleteCmd() *cobra.Command {
	var certificate string
	backendUrl := ""
	var certificateListCmd = &cobra.Command{
		Use:   "delete-custom",
		Short: "Delete a custom certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			err := c.DeleteCustomCertificate(certificate)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := certificateListCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	certificateListCmd.MarkFlagRequired("backend-url")
	flags.StringVarP(&certificate, "certificate", "c", "", "")
	certificateListCmd.MarkFlagRequired("certificate")

	return certificateListCmd
}

func newCertificatesCustomAddCmd() *cobra.Command {
	var certificates string
	var pem string
	backendUrl := ""
	var certificateListCmd = &cobra.Command{
		Use:   "add-custom",
		Short: "Add a custom certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			pemBytes, err := ioutil.ReadFile(pem)
			if err != nil {
				return err
			}

			err = c.AddCustomCertificate(certificates, pemBytes)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := certificateListCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	certificateListCmd.MarkFlagRequired("backend-url")
	flags.StringVarP(&certificates, "certificate", "c", "", "")
	certificateListCmd.MarkFlagRequired("certificate")
	flags.StringVarP(&pem, "pem", "p", "", "")
	certificateListCmd.MarkFlagRequired("pem")

	return certificateListCmd
}

func newCertificatesAddCmd() *cobra.Command {
	var certificates []string
	backendUrl := ""
	var certificateAddCmd = &cobra.Command{
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
	flags := certificateAddCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	certificateAddCmd.MarkFlagRequired("backend-url")
	flags.StringArrayVarP(&certificates, "certificate", "c", []string{}, "")
	certificateAddCmd.MarkFlagRequired("certificate")

	return certificateAddCmd
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
