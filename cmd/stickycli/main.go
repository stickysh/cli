package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/stickysh/cli/commands"
	"io"
	"io/ioutil"
	"log"

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

func zipFolder(root string) (io.Reader, error) {
	buf := new(bytes.Buffer)

	w := zip.NewWriter(buf)
	defer w.Close()

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		zipPath := path
		if filepath.IsAbs(root) {
			zipPath, err = filepath.Rel(root, path)
			if err != nil {
				return err
			}
		}

		f, err := w.Create(zipPath)
		if err != nil {
			return err
		}

		_, err = io.Copy(f, file)
		if err != nil {
			return err
		}

		return nil
	}

	err := filepath.Walk(root, walker)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func InitCliServices(host string) *cliServices {
	cfg := internal.NewConfig(host, "")
	cfg.Auth, _ = cfg.LoadAuth()

	if cfg.Auth.AccessToken != "" && commands.ShouldRefresh(cfg.Auth.AccessToken) {
		auth := commands.RefreshToken(cfg.RemoteHost, cfg.Auth.RefreshToken)
		cfg.UpdateConf(auth)
	}

	remote := internal.NewForgeClient(cfg.RemoteHost, cfg.Auth)

	return &cliServices{
		cfg,
		remote,
	}
}

type cliServices struct {
	cfg    *internal.CliConf
	remote *internal.ForgeClient
}

func main() {
	// TODO: First time use
	// Add Default actions

	var cliSvc *cliServices

	app := &cli.App{
		Name:    "sticky",
		Version: "v0.9-alpha",
		Usage:   "Create wonderful automation to ease your daily routine",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "host",
				Value:   "https://sticky.sh",
				Usage:   "Remote host",
				EnvVars: []string{"REMOTE_HOST"},
			},
		},
		Before: func(c *cli.Context) error {
			cliSvc = InitCliServices(c.String("host"))
			return nil
		},
		Commands: []*cli.Command{
			{
				Name: "login",
				Action: func(c *cli.Context) error {
					auth, err := commands.Login(cliSvc.remote)
					if err != nil {
						return nil
					}
					cliSvc.cfg.UpdateConf(auth)
					return err
				},
			},
			{
				Name: "logout",
				Action: func(c *cli.Context) error {
					cliSvc.cfg.DeleteConf()
					return nil
				},
			},
			{
				Name:  "action",
				Usage: "manage actions on sticky.sh",
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

							jsonDef, err := loadDefFile(defPath)
							if err != nil {
								return err
							}

							ep := fmt.Sprintf("/api/%s/actions/%s", cliSvc.cfg.Auth.Username, tag)
							// Issue request
							req, err := cliSvc.remote.NewRequest(http.MethodPost, ep, bytes.NewBuffer(jsonDef))
							if err != nil {
								return err
							}

							resp, err := cliSvc.remote.Do(req)
							if err != nil {
								return err
							}

							// TODO: respond to specif errors, 400/404/409

							if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
								return err
							}

							fileReader, err := zipFolder(actionPath)
							if err != nil {
								return err
							}

							ep = fmt.Sprintf("%s/actions/%s/code", cliSvc.cfg.Auth.Username, tag)
							resp, err = cliSvc.remote.Upload(ep, fileReader)
							if err != nil {
								return err
							}

							if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
								return err
							}

							fmt.Printf("Action %s updated\n", tag)
							return nil
						},
					},
					{
						Name:        "list",
						Description: "Lists all the actions under your account",
						Aliases:     []string{"ls"},
						Action: func(c *cli.Context) error {
							var respStruct []struct {
								ID          string    `json:"id"`
								Name        string    `json:"name"`
								Description string    `json:"description"`
								IsActive    bool      `json:"is_active"`
								IsPublic    bool      `json:"is_public"`
								CreatedAt   time.Time `json:"updated_at"`
							}

							ep := fmt.Sprintf("/%s/actions", cliSvc.cfg.Auth.Username)
							req, err := cliSvc.remote.NewApiRequest(http.MethodGet, ep, nil)
							if err != nil {
								return err
							}

							resp, err := cliSvc.remote.Do(req)
							if err != nil {
								return err
							}

							if resp.StatusCode == http.StatusUnauthorized {
								internal.OutError("you are not connected, please login")
								return nil
							}

							if resp.StatusCode != http.StatusOK {
								internal.OutError("an error occurred")
								return nil
							}

							bodyRaw, err := ioutil.ReadAll(resp.Body)

							json.Unmarshal(bodyRaw, &respStruct)

							out := make([][]string, len(respStruct))
							for i, v := range respStruct {
								out[i] = []string{fmt.Sprintf(v.ID), fmt.Sprintf(v.Name), fmt.Sprintf("%v", v.IsPublic), fmt.Sprintf("%v", v.IsActive), v.CreatedAt.Format("2006-01-02")}
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

							ep := fmt.Sprintf("%s/secrets/key", cliSvc.cfg.Auth.Username)
							req, err := cliSvc.remote.NewRequest(http.MethodGet, ep, bytes.NewBuffer([]byte{}))
							if err != nil {
								return err
							}

							resp, err := cliSvc.remote.Do(req)
							var secretDef struct {
								Key []byte
							}

							bodyRaw, err := ioutil.ReadAll(resp.Body)
							if err != nil {
								return err
							}

							json.Unmarshal(bodyRaw, &secretDef)

							pubBlock, _ := pem.Decode(secretDef.Key)
							if pubBlock == nil {
								return fmt.Errorf("incorrect PEM")
							}

							pubKey, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
							if err != nil {
								return err
							}

							if err != nil {
								return err
							}

							encryptedBytes, err := rsa.EncryptOAEP(
								sha256.New(),
								rand.Reader,
								pubKey,
								[]byte(secretValue),
								nil)
							if err != nil {
								panic(err)
							}

							reqSecretData := struct {
								Name  string `json:"name"`
								Value string `json:"value"`
							}{
								secretName,
								base64.StdEncoding.EncodeToString(encryptedBytes),
							}

							jsonData, _ := json.Marshal(reqSecretData)

							ep = fmt.Sprintf("%s/secrets", cliSvc.cfg.Auth.Username)
							req, err = cliSvc.remote.NewRequest(http.MethodPost, ep, bytes.NewBuffer(jsonData))
							if err != nil {
								return err
							}

							resp, err = cliSvc.remote.Do(req)
							if err != nil {
								return err
							}

							log.Println(resp)
							log.Println(err)
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
							var respSecretData []struct {
								ID        string    `json:"id"`
								Name      string    `json:"name"`
								CreatedAt time.Time `json:"created_at"`
							}

							ep := fmt.Sprintf("%s/secrets", cliSvc.cfg.Auth.Username)
							req, err := cliSvc.remote.NewRequest(http.MethodGet, ep, nil)
							if err != nil {
								return err
							}

							resp, err := cliSvc.remote.Do(req)
							if err != nil {
								return err
							}

							bodyRaw, err := ioutil.ReadAll(resp.Body)

							json.Unmarshal(bodyRaw, &respSecretData)

							out := make([][]string, len(respSecretData))
							for i, v := range respSecretData {
								out[i] = []string{fmt.Sprintf(v.ID), fmt.Sprintf(v.Name), v.CreatedAt.Format("2006-01-02")}
							}
							internal.OutResult([]string{"SECRET ID", "NAME", "CREATED"}, out)
							return nil
						},
					},
				},
			},
			{
				Name: "flow",
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

							jsonDef, err := loadDefFile(defPath)
							if err != nil {
								return err
							}

							ep := fmt.Sprintf("%s/flows/%s", cliSvc.cfg.Auth.Username, tag)
							req, err := cliSvc.remote.NewApiRequest(http.MethodPost, ep, bytes.NewBuffer(jsonDef))
							if err != nil {
								return err
							}

							resp, err := cliSvc.remote.Do(req)
							if err != nil {
								return err
							}

							// TODO: Move Auth/Login check to central location
							if resp.StatusCode == http.StatusUnauthorized {
								internal.OutError("you are not connected, please login")
								return nil
							}

							if resp.StatusCode != http.StatusOK {
								internal.OutError("remote server responded with and error")
								return nil
							}

							ep = fmt.Sprintf("%s/flows/%s/deploy", cliSvc.cfg.Auth.Username, tag)
							req, err = cliSvc.remote.NewApiRequest(http.MethodPut, ep, bytes.NewBuffer(jsonDef))
							if err != nil {
								return err
							}

							resp, err = cliSvc.remote.Do(req)
							if err != nil {
								return err
							}

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

							//if c.Args().Len() != 1 {
							//	return fmt.Errorf("please provide flow name")
							//}

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

							fmt.Println(payload)
							ep := fmt.Sprintf("%s/flows/%s/run", cliSvc.cfg.Auth.Username, tag)
							req, err := cliSvc.remote.NewApiRequest(http.MethodPost, ep, bytes.NewBuffer([]byte(payload)))
							if err != nil {
								return err
							}

							resp, err := cliSvc.remote.Do(req)
							if err != nil {
								return err
							}
							fmt.Println(resp)
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
							var respStruct []struct {
								ID          string    `json:"id"`
								Name        string    `json:"name"`
								Description string    `json:"description"`
								IsActive    bool      `json:"is_active"`
								CreatedAt   time.Time `json:"updated_at"`
							}

							ep := fmt.Sprintf("%s/flows", cliSvc.cfg.Auth.Username)
							req, err := cliSvc.remote.NewApiRequest(http.MethodGet, ep, nil)
							if err != nil {
								return err
							}

							resp, err := cliSvc.remote.Do(req)
							if err != nil {
								return err
							}

							if resp.StatusCode == http.StatusUnauthorized {
								internal.OutError("you are not connected, please login")
								return nil
							}

							if resp.StatusCode != http.StatusOK {
								internal.OutError("an error occurred")
								return nil
							}

							bodyRaw, err := ioutil.ReadAll(resp.Body)
							log.Println(string(bodyRaw))
							json.Unmarshal(bodyRaw, &respStruct)

							out := make([][]string, len(respStruct))
							for i, v := range respStruct {
								out[i] = []string{fmt.Sprintf(v.ID), fmt.Sprintf(v.Name), fmt.Sprintf("%v", v.IsActive), v.CreatedAt.Format("2006-01-02")}
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
