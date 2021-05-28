package command

import (
	"bytes"
	"fmt"
	"github.com/stickysh/cli/internal"
	"net/http"
)

func ActionCreate(remote *internal.ForgeClient, path string, manifeset string, tag string) error {
	jsonDef, err := loadDefFile(manifeset)
	if err != nil {
		return err
	}

	// TODO: Move to sdk
	ep := remote.ActionEP(tag)
	// Issue request
	req, err := remote.NewRequest(http.MethodPost, ep, bytes.NewBuffer(jsonDef))
	if err != nil {
		return err
	}

	resp, err := remote.Do(req)
	if err != nil {
		return err
	}

	// TODO: respond to specif errors, 400/404/409

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return err
	}

	fileReader, err := zipFolder(path)
	if err != nil {
		return err
	}

	ep = remote.ActionUploadEP(tag)
	resp, err = remote.Upload(ep, fileReader)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return err
	}

	fmt.Printf("Action %s updated\n", tag)
}
