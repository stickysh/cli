package command

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
	"github.com/stickysh/cli/internal"
	"io/ioutil"
	"net/http"
)

func SecretCreate(remote *internal.ForgeClient, name string, value string) error {
	ep := remote.SecretKeyEP()
	req, err := remote.NewRequest(http.MethodGet, ep, bytes.NewBuffer([]byte{}))
	if err != nil {
		return err
	}

	resp, err := remote.Do(req)
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
		[]byte(value),
		nil)
	if err != nil {
		panic(err)
	}

	reqSecretData := struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}{
		name,
		base64.StdEncoding.EncodeToString(encryptedBytes),
	}

	jsonData, _ := json.Marshal(reqSecretData)

	ep = remote.SecretEP()
	req, err = remote.NewRequest(http.MethodPost, ep, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	resp, err = remote.Do(req)
	if err != nil {
		return err
	}

	return nil
}
