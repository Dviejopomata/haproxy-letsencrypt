package frontend

import (
	"fmt"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/client"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/types"
	"github.com/alexeyco/simpletable"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"strconv"
	"strings"
)

func NewFrontendCmd() *cobra.Command {
	var frontendCmd = &cobra.Command{
		Use:   "frontend",
		Short: "Management of all frontends",
	}
	frontendCmd.AddCommand(newFrontendListCmd(), newFrontendAddCmd(), newFrontendDeleteCmd())
	return frontendCmd
}

func newFrontendListCmd() *cobra.Command {
	backendUrl := ""
	o := types.FrontendListOptions{}
	var frontendListCmd = &cobra.Command{
		Use:   "list",
		Short: "Lists all frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			r, err := c.ListFrontends(o)
			if err != nil {
				return err
			}
			table := simpletable.New()

			table.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "Name"},
					{Align: simpletable.AlignCenter, Text: "Port"},
					{Align: simpletable.AlignCenter, Text: "Mode"},
					{Align: simpletable.AlignCenter, Text: "Ssl"},
					{Align: simpletable.AlignCenter, Text: "Lines"},
				},
			}
			for _, frontend := range r.Frontends {
				r := []*simpletable.Cell{
					{Text: frontend.Name},
					{Text: strconv.FormatInt(frontend.Port, 10)},
					{Text: frontend.Mode},
					{Text: strconv.FormatBool(frontend.Ssl)},
					{Text: strings.Join(frontend.Lines, "\n")},
				}
				table.Body.Cells = append(table.Body.Cells, r)
			}
			table.SetStyle(simpletable.StyleCompactLite)
			fmt.Println(table.String())
			return nil
		},
	}
	flags := frontendListCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	frontendListCmd.MarkFlagRequired("backend-url")

	return frontendListCmd
}

func newFrontendDeleteCmd() *cobra.Command {
	backendUrl := ""
	o := types.FrontendDeleteOptions{}
	var frontendDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Delete a backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			err := c.DeleteFrontend(o)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := frontendDeleteCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	frontendDeleteCmd.MarkFlagRequired("backend-url")

	flags.StringVarP(&o.Name, "name", "n", "", "")

	frontendDeleteCmd.MarkFlagRequired("name")

	return frontendDeleteCmd
}

func newFrontendAddCmd() *cobra.Command {
	backendUrl := ""
	o := types.FrontendAddOptions{}
	var frontendAddCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new frontend",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.NewHttpClient(backendUrl)
			if o.Port == 0 && o.Bind == "" {
				return errors.New("--port or --bind need to be set")
			}
			err := c.AddFrontend(o)
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := frontendAddCmd.Flags()
	flags.StringVar(&backendUrl, "backend-url", "b", "Server url")
	frontendAddCmd.MarkFlagRequired("backend-url")

	flags.BoolVar(&o.Ssl, "ssl", false, "Ssl activated")
	flags.Int64VarP(&o.Port, "port", "p", 0, "")
	flags.StringVarP(&o.Bind, "bind", "b", "", "")
	flags.StringVarP(&o.Name, "name", "n", "", "")
	flags.StringVarP(&o.Options, "options", "o", "", "")
	flags.StringVarP(&o.Mode, "mode", "m", "http", "")
	flags.StringArrayVarP(&o.Lines, "line", "l", []string{}, "")

	frontendAddCmd.MarkFlagRequired("name")

	return frontendAddCmd
}
