package backend

import (
	"fmt"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/client"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/types"
	"github.com/alexeyco/simpletable"
	"github.com/spf13/cobra"
	"strings"
)

func NewBackendCmd() *cobra.Command {
	var backendCmd = &cobra.Command{
		Use:   "backend",
		Short: "Management of all backends",
	}
	backendCmd.AddCommand(newBackendAddCmd(), newBackendDeleteCmd(), newBackendListCmd())
	return backendCmd
}

func newBackendListCmd() *cobra.Command {
	backendUrl := ""
	o := types.BackendListOptions{}
	var backendListCmd = &cobra.Command{
		Use:     "list",
		Short:   "List all backends",
		Example: "haproxy-lestencrypt backend list -f http",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			r, err := c.ListBackends(o)
			if err != nil {
				return err
			}
			table := simpletable.New()

			table.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "Host"},
					{Align: simpletable.AlignCenter, Text: "Mode"},
					{Align: simpletable.AlignCenter, Text: "Default"},
					{Align: simpletable.AlignCenter, Text: "Servers"},
				},
			}
			for _, backend := range r.Frontend.Backends {
				var addresses []string
				for _, server := range backend.Servers {
					addresses = append(addresses, server.Address)
				}
				r := []*simpletable.Cell{
					{Text: backend.Host},
					{Text: backend.Mode},
					{Text: fmt.Sprintf("%v", backend.Default)},
					{Text: strings.Join(addresses, ", ")},
				}

				table.Body.Cells = append(table.Body.Cells, r)
			}
			table.SetStyle(simpletable.StyleCompactLite)
			fmt.Println(table.String())
			return nil
		},
	}
	flags := backendListCmd.Flags()
	flags.StringVarP(&o.Frontend, "frontend", "f", "", "")
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	backendListCmd.MarkFlagRequired("frontend")
	backendListCmd.MarkFlagRequired("backend-url")

	return backendListCmd
}

func newBackendDeleteCmd() *cobra.Command {
	backendUrl := ""
	o := types.BackendDeleteOptions{}
	var backendDeleteCmd = &cobra.Command{
		Use:     "delete",
		Short:   "Delete a backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			err := c.DeleteBackend(o)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := backendDeleteCmd.Flags()

	flags.StringVarP(&o.Frontend, "frontend", "f", "", "Frontend name")
	backendDeleteCmd.MarkFlagRequired("frontend")
	flags.StringVar(&o.Host, "host", "", "")
	flags.StringVar(&o.Mode, "mode", "http", "")
	flags.StringVar(&o.Path, "path", "", "")
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	backendDeleteCmd.MarkFlagRequired("backend-url")

	return backendDeleteCmd
}

func newBackendAddCmd() *cobra.Command {
	backendUrl := ""
	o := types.BackendAddOptions{}
	var backendAddCmd = &cobra.Command{
		Use:     "add",
		Short:   "Adds a new backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			err := c.AddBackend(o)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := backendAddCmd.Flags()
	flags.StringArrayVarP(&o.Address, "address", "a", []string{}, "")
	backendAddCmd.MarkFlagRequired("address")
	flags.BoolVar(&o.Default, "default-backend", false, "")
	flags.StringArrayVarP(&o.Options, "option", "o", []string{}, "")
	flags.StringArrayVarP(&o.Frontend, "frontend", "f", []string{}, "Frontend name")
	backendAddCmd.MarkFlagRequired("frontend")
	flags.StringVar(&o.Host, "host", "", "")
	flags.StringVar(&o.Path, "path", "", "")
	flags.StringVar(&o.Mode, "mode", "http", "")
	flags.StringVar(&o.If, "if", "", "")

	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	backendAddCmd.MarkFlagRequired("backend-url")

	return backendAddCmd
}
