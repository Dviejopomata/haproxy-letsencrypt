package le

import (
	"github.com/Dviejopomata/haproxy-letsencrypt/log"
	"io/ioutil"
	"os"
	"path/filepath"
)

type HTTPProviderServer struct {
}

func NewHTTPProviderServer() *HTTPProviderServer {
	return &HTTPProviderServer{}
}

// Present starts a web server and makes the token available at `HTTP01ChallengePath(token)` for web requests.
func (s *HTTPProviderServer) Present(domain, token, keyAuth string) error {
	log.Printf("Cleanup domain=%s token=%s keyAuth=%s", domain, token, keyAuth)
	tokenPath := filepath.Join(os.TempDir(), token)
	var err error
	err = os.MkdirAll(filepath.Base(tokenPath), os.ModePerm)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(tokenPath, []byte(keyAuth), os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

// CleanUp closes the HTTP server and removes the token from `HTTP01ChallengePath(token)`
func (s *HTTPProviderServer) CleanUp(domain, token, keyAuth string) error {
	log.Printf("Cleanup domain=%s token=%s keyAuth=%s", domain, token, keyAuth)
	return nil
}
