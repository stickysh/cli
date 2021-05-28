package command

import (
	"encoding/json"
	"github.com/stickysh/cli/internal"
	"io/ioutil"
	"net/http"
	"time"
)

type SecretResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func SecretList(remote *internal.ForgeClient) ([]SecretResponse, error) {

	ep := remote.SecretEP()
	req, err := remote.NewRequest(http.MethodGet, ep, nil)
	if err != nil {
		return nil, err
	}

	resp, err := remote.Do(req)
	if err != nil {
		return nil, err
	}

	bodyRaw, err := ioutil.ReadAll(resp.Body)

	var res []SecretResponse

	err = json.Unmarshal(bodyRaw, &res)
	if err != nil {
		return nil, err
	}

	return res, nil

}
