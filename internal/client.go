package internal

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

var (
	version = "v1.0"
	agent   = fmt.Sprintf("sticky-cli/%s", version)
)

type ForgeClient struct {
	client *http.Client
	auth   *AuthCred
	Host   string
}

func NewForgeClient(host string, auth *AuthCred) *ForgeClient {
	return &ForgeClient{
		&http.Client{
			Timeout: 120 * time.Second,
		},
		auth,
		host,
	}
}

func (fa *ForgeClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", agent)
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	return fa.client.Do(req)
}

func (fa *ForgeClient) Upload(ep string, fileReader io.Reader) (*http.Response, error) {
	bodyBuf := &bytes.Buffer{}
	mw := multipart.NewWriter(bodyBuf)
	part, err := mw.CreateFormField("file")
	if err != nil {
		return nil, err
	}
	defer mw.Close()

	io.Copy(part, fileReader)

	req, err := fa.NewRequest(http.MethodPut, ep, bodyBuf)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", agent)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	return fa.client.Do(req)
}

func (fa *ForgeClient) NewApiRequest(method, ep string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s/api/%s", fa.Host, ep), body)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", fa.auth.AccessToken))

	return req, err
}

func (fa *ForgeClient) NewAuthRequest(method, ep string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s/auth/%s", fa.Host, ep), body)

	return req, err
}

func (fa *ForgeClient) NewRequest(method, ep string, body io.Reader) (*http.Request, error) {
	return http.NewRequest(method, fmt.Sprintf("%s/%s", fa.Host, ep), body)
}

func (fa *ForgeClient) ActionUploadEP(tag string) string {
	return fmt.Sprintf("%s/actions/%s/code", fa.auth.Username, tag)
}

func (fa *ForgeClient) ActionEP(tag string) string {
	return fmt.Sprintf("%s/actions/%s", fa.auth.Username, tag)
}

func (fa *ForgeClient) ActionsEP() string {
	return fmt.Sprintf("%s/actions", fa.auth.Username)
}

func (fa *ForgeClient) SecretEP() string {
	return fmt.Sprintf("%s/actions", fa.auth.Username)
}

func (fa *ForgeClient) SecretKeyEP() string {
	return fmt.Sprintf("%s/secrets/key", fa.auth.Username)
}
