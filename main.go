package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/stickysh/cli/command"

	"net/http"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"

	"time"

	"github.com/urfave/cli/v2"

	"github.com/stickysh/cli/internal"
)

func loadDefFile(path string) ([]byte, error) {
	rawDef, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadAll(rawDef)
	jsonDef, err := yaml.YAMLToJSON(buf)
	if err != nil {
		return nil, err
	}

	return jsonDef, nil
}

func InitCliServices(host string, confPath string) (*cliServices, error) {
	cfg := internal.NewConfig(host, confPath)
	cred, err := cfg.LoadAuth()
	if err != nil {
		return &cliServices{
			cfg,
			nil,
		}, nil
	}

	cfg.Auth = cred
	if cfg.Auth.AccessToken != "" && command.ShouldRefresh(cfg.Auth.AccessToken) {
		auth := command.RefreshToken(cfg.RemoteHost, cfg.Auth.RefreshToken)
		cfg.UpdateConf(auth)
	}

	remote := internal.NewForgeClient(cfg.RemoteHost, cfg.Auth)

	return &cliServices{
		cfg,
		remote,
	}, nil
}

type cliServices struct {
	cfg    *internal.CliConf
	remote *internal.ForgeClient
}

var vesrion = "v0.9.0"

func main() {
	// TODO: First time use
	// Add Default actions

	var cliSvc *cliServices

	cli.AppHelpTemplate = `
   {{.Name}} - {{.Usage}}
USAGE
   {{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
   {{if len .Authors}}
COMMANDS
{{range .Commands}}{{if not .HideHelp}}   {{join .Names ", "}}{{ "\t"}}{{.Usage}}{{ "\n" }}{{end}}{{end}}{{end}}{{if .VisibleFlags}}
GLOBAL OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}{{end}}{{if .Copyright }}
VERSION:
   {{.Version}}
   {{end}}
`
	app := &cli.App{
		Name:        "sticky",
		Description: "CLI to Build ",
		Version:     vesrion,
		Usage:       "Create wonderful automations to ease your daily routine",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "host",
				Value:   "http://forgesvc.sticky.sh",
				Usage:   "Remote host",
				EnvVars: []string{"REMOTE_HOST"},
			},
		},
		Before: func(c *cli.Context) error {
			// TODO
			_, err := InitCliServices(c.String("host"), ".sticky")
			if err != nil {
				internal.OutError("")
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name: "version",
				Action: func(c *cli.Context) error {
					internal.OutInfo(fmt.Sprintf("sticky/%s", vesrion))
					return nil
				},
			},
			{
				Name:   "login",
				Hidden: true,
				Action: func(c *cli.Context) error {
					auth, err := command.Login(cliSvc.remote)
					if err != nil {
						return nil
					}
					cliSvc.cfg.UpdateConf(auth)
					return err
				},
			},
			{
				Name:   "logout",
				Hidden: true,
 				Action: func(c *cli.Context) error {
					cliSvc.cfg.DeleteConf()
					return nil
				},
			},
			{
				Name:  "actions",
				Usage: "Create and manage actions on sticky.sh",
				Subcommands: []*cli.Command{
					{
						Name:        "create",
						Description: "create the action and push the code to sticky.sh",
						Usage:       " ",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "file",
								Aliases: []string{"f"},
							},
							&cli.StringFlag{
								Name:    "tag",
								Aliases: []string{"t"},
							},
						},
						Action: func(c *cli.Context) error {
							if c.Args().Len() != 1 {
								return fmt.Errorf("please provide action path")
							}

							actionPath := cliSvc.cfg.WD
							if c.Args().Len() > 0 {
								arg := c.Args().First()
								if arg != "." {
									actionPath = arg
								}
							}

							defPath := fmt.Sprintf("%s/action.yaml", actionPath)
							if c.IsSet("file") {
								defPath = c.String("file")
								ext := filepath.Ext(defPath)
								if ext != ".yaml" && ext != ".yml" {
									return fmt.Errorf("path has no action definition")
								}
							}

							if _, err := os.Stat(defPath); err != nil {
								if os.IsNotExist(err) {
									return fmt.Errorf("action definition was not found in the path or provided with flag")
								}
							}

							var tag string
							if c.IsSet("tag") {
								tag = c.String("tag")
							} else {
								return fmt.Errorf("please tag the new action")
							}

							command.ActionCreate(cliSvc.remote, actionPath, defPath, tag)

							return nil
						},
					},
					{
						Name:        "list",
						Description: "Lists all the actions under your account",
						Aliases:     []string{"ls"},
						Action: func(c *cli.Context) error {
							res, err := command.ActionList(cliSvc.remote)
							if err != nil {
								return err
							}

							out := make([][]string, len(res))
							for i, v := range res {
								out[i] = []string{
									fmt.Sprintf(v.ID),
									fmt.Sprintf(v.Name),
									fmt.Sprintf("%v", v.IsPublic),
									fmt.Sprintf("%v", v.IsActive),
									v.CreatedAt.Format("2006-01-02"),
								}
							}

							internal.OutResult([]string{"ACTION ID", "NAME", "PUBLIC", "ACTIVE", "UPDATED"}, out)
							return nil
						},
					},
				},
			},
			{
				Name: "secrets",
				Subcommands: []*cli.Command{
					{
						Name:        "create",
						Description: "create a secret",
						Action: func(c *cli.Context) error {
							var secretName string
							var secretValue string

							if c.Args().Len() > 1 {
								secretName = c.Args().First()
								secretValue = c.Args().Get(1)
							}

							err := command.SecretCreate(cliSvc.remote, secretName, secretValue)

							return nil
						},
					},
					{
						Name:        "delete",
						Aliases:     []string{"del"},
						Description: "delete a secret",
						Action: func(c *cli.Context) error {

							return nil
						},
					},
					{
						Name:    "list",
						Aliases: []string{"ls"},
						Action: func(c *cli.Context) error {

							res, err := command.SecretList(cliSvc.remote)
							if err != nil {
								return err
							}

							out := make([][]string, len(res))
							for i, v := range res {
								out[i] = []string{
									fmt.Sprintf(v.ID),
									fmt.Sprintf(v.Name),
									v.CreatedAt.Format("2006-01-02")
								}
							}

							internal.OutResult([]string{"SECRET ID", "NAME", "CREATED"}, out)
							return nil
						},
					},
				},
			},
			{
				Name: "flows",
				Subcommands: []*cli.Command{
					{
						Name: "create",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "file",
								Aliases: []string{"f"},
							},
							&cli.StringFlag{
								Name:    "tag",
								Aliases: []string{"t"},
							},
						},
						Action: func(c *cli.Context) error {

							flowPath := cliSvc.cfg.WD

							defPath := fmt.Sprintf("%s/flow.yaml", flowPath)
							if c.IsSet("file") {
								defPath = c.String("file")
								ext := filepath.Ext(defPath)
								if ext != ".yaml" && ext != ".yml" {
									return fmt.Errorf("no flow definition was provided")
								}
							}

							if _, err := os.Stat(defPath); err != nil {
								if os.IsNotExist(err) {
									return fmt.Errorf("action definition was not found in path or provided")
								}
							}

							var tag string
							if c.IsSet("tag") {
								tag = c.String("tag")
							} else {
								return fmt.Errorf("please tag the new flow")
							}

							command.FlowCreate(cliSvc.remote, tag, defPath)
							return nil
						},
					},
					{
						Name: "run",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:    "payload",
								Aliases: []string{"p"},
							},
						},
						Action: func(c *cli.Context) error {

							var tag string
							if c.Args().Len() > 0 {
								tag = c.Args().First()
							}

							var payload string
							if c.IsSet("payload") {
								payload = c.String("payload")
							} else {
								return fmt.Errorf("please provide payload")
							}

							command.FlowRun(cliSvc.remote, tag, payload)

							return nil
						},
					},
					{
						Name: "logs",
					},
					{
						Name: "inspect",
					},
					{
						Name:    "list",
						Aliases: []string{"ls"},
						Action: func(c *cli.Context) error {
							result, err := command.FlowList(cliSvc.remote)
							if err != nil {
								return err
							}

							out := make([][]string, len(result))
							for i, v := range result {
								out[i] = []string{
									fmt.Sprintf(v.ID),
									fmt.Sprintf(v.Name),
									fmt.Sprintf("%v", v.IsActive),
									v.CreatedAt.Format("2006-01-02"),
								}
							}
							internal.OutResult([]string{"ACTION ID", "NAME", "ACTIVE", "UPDATED"}, out)
							return nil
						},
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
