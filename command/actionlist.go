package command

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/stickysh/cli/internal"
)

type ActionResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	IsPublic    bool      `json:"is_public"`
	CreatedAt   time.Time `json:"updated_at"`
}

func ActionList(remote *internal.ForgeClient) ([]ActionResponse, error) {

	ep := remote.ActionsEP()
	req, err := remote.NewApiRequest(http.MethodGet, ep, nil)
	if err != nil {
		return nil, err
	}

	resp, err := remote.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("you are not connected, please login")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("an error occurred")
	}

	bodyRaw, err := ioutil.ReadAll(resp.Body)

	var respStruct []ActionResponse

	err = json.Unmarshal(bodyRaw, &respStruct)
	if err != nil {
		return nil, err
	}

	return respStruct, nil
}
