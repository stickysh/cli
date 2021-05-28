package internal

import (
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/pelletier/go-toml"
)

type CliConf struct {
	Auth       *AuthCred
	RemoteHost string
	WD         string
	ConfPath   string
}

type AuthFile struct {
	Auth AuthCred
}

type AuthCred struct {
	Username     string
	AccessToken  string
	RefreshToken string
}

func NewConfig(host string, path string) *CliConf {
	pwd, _ := os.Getwd()

	return &CliConf{
		Auth:       &AuthCred{},
		RemoteHost: host,
		WD:         pwd,
		ConfPath:   path,
	}

}

func (c CliConf) LoadAuth() (*AuthCred, error) {
	usr, err := user.Current()

	var authConf AuthFile

	confFile, err := ioutil.ReadFile(filepath.Join(usr.HomeDir, c.ConfPath, "credentials"))
	if err != nil {
		return nil, err
	}
	toml.Unmarshal(confFile, &authConf)

	return &authConf.Auth, nil
}

func (c *CliConf) UpdateConf(auth *AuthCred) error {
	data, err := toml.Marshal(AuthFile{Auth: *auth})
	if err != nil {
		return err
	}
	usr, err := user.Current()
	return ioutil.WriteFile(filepath.Join(usr.HomeDir, c.ConfPath), data, os.ModePerm|0644)
}

func (c *CliConf) DeleteConf() error {
	return os.Remove(c.ConfPath)
}
