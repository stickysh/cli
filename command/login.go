package command

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os/exec"
	"time"

	"github.com/briandowns/spinner"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/oklog/ulid/v2"

	"github.com/stickysh/cli/internal"
)

func Login(remote *internal.ForgeClient) (*internal.AuthCred, error) {
	t := time.Unix(1000000, 0)
	entropy := ulid.Monotonic(mathrand.New(mathrand.NewSource(t.UnixNano())), 0)
	tempCliID := ulid.MustNew(ulid.Timestamp(t), entropy)

	privkey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return nil, err
	}

	key, err := jwk.New(&privkey.PublicKey)
	if err != nil {
		log.Printf("failed to create JWK: %s", err)
		return nil, err
	}

	n, _ := key.Get("n")
	encKey := base64.URLEncoding.EncodeToString(n.([]byte))

	svcLoginAddress := fmt.Sprintf("%s/auth/cli/browser/%s?requester=%s", remote.Host, tempCliID, encKey)

	err = exec.Command("open", svcLoginAddress).Start()
	if err != nil {
		log.Println("could not open the browser")
	}

	var respAuthBody map[string]interface{}
	gotCode := false

	s := spinner.New(spinner.CharSets[2], 100*time.Millisecond)
	s.Prefix = "Waiting for your login "

	s.Color("cyan")
	s.Start()
	defer s.Stop()

	for gotCode != true {
		<-time.After(500 * time.Millisecond)

		req, err := remote.NewRequest("GET", fmt.Sprintf("auth/cli/code/%s", tempCliID), nil)
		resp, err := remote.Do(req)
		if err != nil {
			internal.OutError("remote server could not be reached, check status")
			return nil, err
		}
		if resp.StatusCode == http.StatusLocked {
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		var respAuth struct {
			Code []byte `json:"code"`
		}

		json.Unmarshal(body, &respAuth)
		if err != nil {
			panic(err)
		}

		decryptedBytes, err := privkey.Decrypt(nil, respAuth.Code, &rsa.OAEPOptions{Hash: crypto.SHA1})
		respBodyRaw := getToken(remote.Host, string(decryptedBytes))
		json.Unmarshal(respBodyRaw, &respAuthBody)

		gotCode = true

	}

	token, err := jwt.ParseBytes([]byte(respAuthBody["id_token"].(string)))
	username, _ := token.Get("cognito:username")

	s.FinalMSG = fmt.Sprintf("Logged in as %s\n", username)

	return &internal.AuthCred{
		Username:     username.(string),
		AccessToken:  respAuthBody["access_token"].(string),
		RefreshToken: respAuthBody["refresh_token"].(string),
	}, nil
}

type AuthConfig struct {
	AppID          string `json:"app_id"`
	AppTokenURI    string `json:"app_token_uri"`
	AppRedirectURI string `json:"app_redirect_uri"`
}

func getAuthConfig(host string) (*AuthConfig, error) {
	resp, err := http.Get(fmt.Sprintf("%s/auth/cli/config", host))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var authConfig AuthConfig

	json.Unmarshal(body, &authConfig)
	return &authConfig, nil
}

func ShouldRefresh(accessToken string) bool {
	token, err := jwt.ParseBytes([]byte(accessToken))
	if err != nil {
		return true
	}

	rawExp, _ := token.Get("exp")
	exp := rawExp.(time.Time)

	return time.Now().Unix() >= exp.Unix()
}

func RefreshToken(host string, refreshToken string) *internal.AuthCred {

	authConf, err := getAuthConfig(host)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", authConf.AppID)
	data.Set("refresh_token", refreshToken)

	// Token
	authResp, err := http.PostForm(authConf.AppTokenURI, data)
	if err != nil {
		log.Fatal(err)
	}
	var respAuthBody map[string]interface{}
	respBodyRaw, err := ioutil.ReadAll(authResp.Body)
	if err != nil {

	}

	json.Unmarshal(respBodyRaw, &respAuthBody)

	token, err := jwt.ParseBytes([]byte(respAuthBody["id_token"].(string)))
	username, _ := token.Get("cognito:username")

	return &internal.AuthCred{
		Username:     username.(string),
		AccessToken:  respAuthBody["access_token"].(string),
		RefreshToken: refreshToken,
	}

}

func getToken(host string, code string) []byte {

	authConf, err := getAuthConfig(host)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", authConf.AppID)
	data.Set("code", code)
	data.Set("redirect_uri", authConf.AppRedirectURI)

	// Token
	authResp, err := http.PostForm(authConf.AppTokenURI, data)
	if err != nil {

	}

	respBodyRaw, err := ioutil.ReadAll(authResp.Body)
	if err != nil {

	}

	return respBodyRaw
}
