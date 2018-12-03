package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/types"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

type Client struct {
	BaseURL    string
	httpClient *http.Client
}

func NewHttpClient(backendUrl string) *Client {
	client := &Client{
		BaseURL:    backendUrl,
		httpClient: &http.Client{},
	}
	return client
}

func (c *Client) AddBackend(options types.BackendAddOptions) error {
	post, err := json.Marshal(options)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Post(fmt.Sprintf("%s/backend", c.BaseURL), "application/json", bytes.NewBuffer(post))
	if err != nil {
		return err
	}
	_ = resp
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.Errorf("Failed with status code %d", resp.StatusCode)
}
func (c *Client) ListBackends(options types.BackendListOptions) (r types.BackendListOptionsResponse, err error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/frontend/%s", c.BaseURL, options.Frontend))
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = errors.Errorf("Failed to fetch backends for frontend %s with status %d", options.Frontend, resp.StatusCode)
		return
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(respBytes, &r)
	if err != nil {
		return
	}
	return
}

func (c *Client) DeleteBackend(options types.BackendDeleteOptions) error {

	post, err := json.Marshal(options)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/backend", c.BaseURL), bytes.NewBuffer(post))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.Errorf("Failed with status code %d", resp.StatusCode)
}
func (c *Client) ListFrontends(options types.FrontendListOptions) (r types.FrontendListOptionsResponse, err error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/frontend", c.BaseURL))
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = errors.Errorf("Failed to fetch frontends with status %d", resp.StatusCode)
		return
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	err = json.Unmarshal(respBytes, &r)
	if err != nil {
		return
	}
	return
}
func (c *Client) AddFrontend(options types.FrontendAddOptions) error {
	post, err := json.Marshal(options)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Post(fmt.Sprintf("%s/frontend", c.BaseURL), "application/json", bytes.NewBuffer(post))
	if err != nil {
		return err
	}
	_ = resp
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.Errorf("Failed with status code %d", resp.StatusCode)
}
func (c *Client) DeleteFrontend(options types.FrontendDeleteOptions) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/frontend/%s", c.BaseURL, options.Name), nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.Errorf("Failed with status code %d", resp.StatusCode)
}

func (c *Client) AddCertificate(certificates []string) error {
	post, err := json.Marshal(certificates)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Post(fmt.Sprintf("%s/certificates", c.BaseURL), "application/json", bytes.NewBuffer(post))
	if err != nil {
		return err
	}
	_ = resp
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return errors.Errorf("Failed with status code %d", resp.StatusCode)
}

func (c *Client) RenewCertificate(certificate string) error {
	resp, err := c.httpClient.Post(fmt.Sprintf("%s/certificates/%s/renew", c.BaseURL, certificate), "", nil)
	if err != nil {
		return err
	}
	_ = resp
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return errors.Errorf("Failed with status code %d", resp.StatusCode)
}
