// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Dviejopomata/haproxy-letsencrypt/log"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/lb"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/le"
	naTypes "github.com/Dviejopomata/haproxy-letsencrypt/pkg/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/robfig/cron"
	"github.com/spf13/cobra"
	"github.com/xenolf/lego/acme"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	acmeV2Staging      = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeV2Real         = "https://acme-v02.api.letsencrypt.org/directory"
	haproxyCfgName     = "haproxy.cfg"
	labelDockerCompose = "com.docker.compose.project"
	crtListName        = "crt-list.txt"
	acmeJson           = "acme.json"
	dummyHaproxyConfig = `
global
  daemon
  log 127.0.0.1 local0
  log 127.0.0.1 local1 notice
  maxconn 4096
  tune.ssl.default-dh-param 2048

defaults
  log               global
  retries           3
  maxconn           2000
  timeout connect   5s
  timeout client    50s
  timeout server    50s
frontend http
    bind *:80
`
)

var (
	haproxyContainerName = ""
	caDirUrl             = ""
	dockerCli            *client.Client
)

func readFile(c *gin.Context, name string) ([]byte, error) {
	formFile, err := c.FormFile(name)
	if err != nil {
		return nil, err
	}
	file, err := formFile.Open()
	if err != nil {
		return nil, err
	}
	contents, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

func getHaproxyContainer(dockerCli *client.Client, projectName string) (json types.ContainerJSON, err error) {
	filterArgs := filters.NewArgs()
	ctx := context.Background()
	containers, err := dockerCli.ContainerList(ctx, types.ContainerListOptions{
		Filters: filterArgs,
	})
	if err != nil {
		return json, err
	}
	var haproxyContainer types.Container
	found := false
	for _, container := range containers {
		containerLabel := container.Labels[labelDockerCompose]
		log.Printf("Container %s, project=%s", container.Names[0], containerLabel)
		if containerLabel == projectName {
			if strings.HasPrefix(container.Image, "haproxy:") {
				haproxyContainer = container
				found = true
			}
		}
	}
	if !found {
		return json, errors.New("No haproxy container found")
	}
	json, err = dockerCli.ContainerInspect(ctx, haproxyContainer.ID)
	return
}

func reloadContainer(containerName string) error {
	ctx := context.Background()
	haproxyContainer, err := dockerCli.ContainerInspect(ctx, containerName)
	if err != nil {
		return err
	}
	log.Printf("Killing %s", haproxyContainer.Name)
	if haproxyContainer.State.Status != "running" {
		duration := 10 * time.Second
		err = dockerCli.ContainerRestart(ctx, haproxyContainer.Name, &duration)
		if err != nil {
			return err
		}
	}
	err = dockerCli.ContainerKill(ctx, haproxyContainer.Name, "HUP")
	if err != nil {
		return err
	}
	return nil
}

type ServeOptions struct {
	HaproxyDir         string
	StorageDir         string
	Staging            bool
	BundleCertificates bool
	LetsencryptMail    string
	StatsPort          int
	StatsUser          string
	StatsPassword      string
}

func NewServeCmd() *cobra.Command {
	o := ServeOptions{}
	// serveCmd represents the serve command
	var serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Starts the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			r := gin.Default()

			if o.Staging {
				caDirUrl = acmeV2Staging
			} else {
				caDirUrl = acmeV2Real
			}

			log.Infof("Le staging url=%s staging=%v", caDirUrl, o.Staging)
			dockerCli, err = client.NewClientWithOpts(client.FromEnv)
			if err != nil {
				return err
			}
			ctx := context.Background()
			dockerCli.NegotiateAPIVersion(ctx)
			containerId := os.Getenv("HOSTNAME")
			inspect, err := dockerCli.ContainerInspect(ctx, containerId)
			if err != nil {
				return err
			}
			dockerComposeProject := inspect.Config.Labels[labelDockerCompose]
			log.Printf("Project %s", dockerComposeProject)
			haproxyInspect, err := getHaproxyContainer(dockerCli, dockerComposeProject)
			if err != nil {
				return err
			}
			haproxyContainerName = haproxyInspect.Name

			haproxyCfgPath := filepath.Join(o.HaproxyDir, haproxyCfgName)
			if haproxyCfgPath == "" {
				return errors.New("Haproxy cfg not set")
			}
			_, err = os.Stat(haproxyCfgPath)
			if err != nil {
				err = ioutil.WriteFile(haproxyCfgPath, []byte(dummyHaproxyConfig), os.ModePerm)
				if err != nil {
					return errors.Wrapf(err, "Failed to write haproxy initial config %s", haproxyCfgPath)
				}
				go func() {
					time.Sleep(2 * time.Second)
					err = reloadContainer(haproxyContainerName)
					if err != nil {
						log.Errorf("Failed to reload container %s", haproxyContainerName)
					}
				}()

			}

			configPath := filepath.Join(o.StorageDir, "config.yml")

			if _, err := os.Stat(configPath); err != nil {
				log.Infof("Creating file %s", configPath)
				file, err := os.Create(configPath)
				if err != nil {
					return err
				}
				file.Close()
			}
			certificatesApi, err := NewCertificatesApi(o)
			if err != nil {
				return errors.Wrapf(err, "Failed to initialize certificates api")
			}
			err = certificatesApi.dumpCertificates()
			if err != nil {
				return errors.Wrapf(err, "Failed to dump certificates")
			}
			_, err = certificatesApi.getAcmeClient(o.LetsencryptMail)
			if err != nil {
				return errors.Wrapf(err, "Failed to get acme client")
			}
			err = certificatesApi.dumpAcmeJson()
			if err != nil {
				return errors.Wrapf(err, "Failed to dump acme.json")
			}
			options := lb.Options{
				Stats: lb.Stats{
					Port:     o.StatsPort,
					Password: o.StatsPassword,
					User:     o.StatsUser,
				},
			}
			dumpAll := func(haproxyLb *lb.HaproxyLb) error {
				dumpResponse, err := haproxyLb.Dump()

				err = ioutil.WriteFile(haproxyCfgPath, []byte(dumpResponse.HaproxyConfig), os.ModePerm)
				if err != nil {
					return errors.Wrapf(err, "Failed to write contents to haproxy")
				}
				err = reloadContainer(haproxyContainerName)
				if err != nil {
					return errors.Wrapf(err, "Failed to reload haproxy config")
				}
				err = ioutil.WriteFile(configPath, []byte(dumpResponse.YamlConfig), os.ModePerm)
				if err != nil {
					return err
				}
				err = certificatesApi.dumpCertificates()
				if err != nil {
					return errors.Wrapf(err, "Failed to dump certificates")
				}
				return nil
			}
			_ = r.GET("/dump", func(c *gin.Context) {

				err = certificatesApi.dumpCertificates()
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to dump certificates"))
					return
				}
				c.Status(http.StatusNoContent)
				c.Done()
			})
			_ = r.GET("/reload", func(c *gin.Context) {
				leBytes, err := ioutil.ReadFile(configPath)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read config file"))
					return
				}
				haproxyLb, err := lb.NewHaproxyLb(leBytes, options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to init haproxy lb config"))
					return
				}
				err = dumpAll(haproxyLb)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to dump configuration"))
					return
				}
				c.Status(http.StatusNoContent)
				c.Done()
			})
			_ = r.GET("/frontend", func(c *gin.Context) {
				leBytes, err := ioutil.ReadFile(configPath)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read config file"))
					return
				}
				hlb, err := lb.NewHaproxyLb(leBytes, options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to init haproxy lb config"))
					return
				}
				frontends := hlb.GetFrontends()
				c.JSON(http.StatusOK, naTypes.FrontendListOptionsResponse{
					Frontends: frontends,
				})
			})

			_ = r.GET("/frontend/:name", func(c *gin.Context) {
				leBytes, err := ioutil.ReadFile(configPath)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read config file"))
					return
				}
				hlb, err := lb.NewHaproxyLb(leBytes, options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to init haproxy lb config"))
					return
				}
				frontendName := c.Param("name")
				frontend, err := hlb.GetFrontend(frontendName)
				if err != nil {
					c.AbortWithError(http.StatusNotFound, err)
					return
				}
				c.JSON(http.StatusOK, naTypes.BackendListOptionsResponse{
					Frontend: frontend,
				})
			})

			_ = r.DELETE("/backend", func(c *gin.Context) {
				//DeleteBackend
				leBytes, err := ioutil.ReadFile(configPath)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read config file"))
					return
				}
				haproxyLb, err := lb.NewHaproxyLb(leBytes, options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to init haproxy lb config"))
					return
				}
				backendDeleteOptions := naTypes.BackendDeleteOptions{}
				err = c.BindJSON(&backendDeleteOptions)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read body"))
					return
				}
				err = haproxyLb.DeleteBackend(backendDeleteOptions)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to delete frontend"))
					return
				}
				err = dumpAll(haproxyLb)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to dump configuration"))
					return
				}
				c.Status(http.StatusNoContent)
				c.Done()
			})
			_ = r.DELETE("/frontend/:name", func(c *gin.Context) {
				leBytes, err := ioutil.ReadFile(configPath)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read config file"))
					return
				}
				haproxyLb, err := lb.NewHaproxyLb(leBytes, options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to init haproxy lb config"))
					return
				}
				frontendName := c.Param("name")
				if frontendName == "" {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "frontend name is empty"))
					return
				}
				backendAddOptions := naTypes.FrontendDeleteOptions{
					Name: frontendName,
				}
				err = haproxyLb.DeleteFrontend(backendAddOptions)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to delete frontend"))
					return
				}
				err = dumpAll(haproxyLb)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to dump configuration"))
					return
				}
				c.Status(http.StatusNoContent)
				c.Done()
			})
			_ = r.GET("/certificates/:domain/crt", func(c *gin.Context) {
				certificate, err := certificatesApi.GetCertficate(c.Param("domain"))
				if err != nil {
					c.AbortWithError(http.StatusNotFound, err)
					return
				}
				c.String(http.StatusOK, string(certificate.Crt))

			})
			_ = r.GET("/certificates/:domain/pk", func(c *gin.Context) {
				certificate, err := certificatesApi.GetCertficate(c.Param("domain"))
				if err != nil {
					c.AbortWithError(http.StatusNotFound, err)
					return
				}
				c.String(http.StatusOK, string(certificate.Key))

			})
			_ = r.POST("/frontend", func(c *gin.Context) {
				leBytes, err := ioutil.ReadFile(configPath)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read config file"))
					return
				}
				haproxyLb, err := lb.NewHaproxyLb(leBytes, options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to init haproxy lb config"))
					return
				}
				backendAddOptions := naTypes.FrontendAddOptions{}
				err = c.BindJSON(&backendAddOptions)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read body"))
					return
				}
				err = haproxyLb.AddFrontend(backendAddOptions)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to add frontend"))
					return
				}
				err = dumpAll(haproxyLb)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to dump configuration"))
					return
				}
				c.Status(http.StatusNoContent)
				c.Done()
			})
			_ = r.POST("/certificates/:domain/renew", func(c *gin.Context) {
				domain := c.Param("domain")
				err := certificatesApi.RenewCertificate(o.LetsencryptMail, o.BundleCertificates, domain)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to renew certificates for %s", domain))
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"message": fmt.Sprintf("%s renewed successfully", domain),
				})
			})
			_ = r.GET("/certificates", func(c *gin.Context) {
				crts, err := certificatesApi.GetCertficates(o.LetsencryptMail)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, err)
					return
				}
				c.JSON(http.StatusOK, crts)
			})
			_ = r.GET("/certificatesrenew", func(c *gin.Context) {
				err := certificatesApi.RenewCertificates(o.BundleCertificates)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, err)
					return
				}
				c.Status(http.StatusNoContent)
				c.Done()
			})
			_ = r.POST("/backend", func(c *gin.Context) {
				leBytes, err := ioutil.ReadFile(configPath)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read config file"))
					return
				}
				hlb, err := lb.NewHaproxyLb(leBytes, options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to init haproxy lb config"))
					return
				}
				options := naTypes.BackendAddOptions{}
				err = c.BindJSON(&options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to read body"))
					return
				}
				err = hlb.AddBackend(options)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to add backend"))
					return
				}
				err = dumpAll(hlb)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to dump configuration"))
					return
				}
				if options.ProvisionCertificate && options.Host != "" && !certificatesApi.IsCustomCertificate(options.Host) {
					requireSsl := false
					for _, frontendName := range options.Frontend {
						frontend, err := hlb.GetFrontend(frontendName)
						if err != nil {
							c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to get frontend"))
							return
						}
						if frontend.Ssl {
							requireSsl = frontend.Ssl
							break
						}
					}
					log.Debugf("Backend requires ssl certificate: %v", requireSsl)
					if requireSsl {
						err := certificatesApi.ProvisionCertificates(o.LetsencryptMail, o.BundleCertificates, options.Host)
						if err != nil {
							c.AbortWithError(http.StatusBadRequest, errors.Wrapf(err, "Failed to get certificates for %s", options.Host))
							return
						}
					}
				}

				c.Status(http.StatusNoContent)
				c.Done()
			})
			_ = r.GET("/.well-known/acme-challenge/:token", func(c *gin.Context) {

				var token = c.Param("token")
				tokenPath := filepath.Join(os.TempDir(), token)
				if _, err := os.Stat(tokenPath); err != nil {
					c.JSON(http.StatusNotFound, gin.H{
						"message": fmt.Sprintf("Token %s not found", token),
					})
					return
				}

				keyAuthBytes, err := ioutil.ReadFile(tokenPath)
				if err != nil {
					c.AbortWithError(http.StatusInternalServerError, err)
					return
				}
				c.Header("Content-type", "text/plain")
				c.String(200, string(keyAuthBytes))

			})
			_ = r.POST("/certificates/:domain/custom", func(c *gin.Context) {
				file, err := readFile(c, "pem")
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Missing \"pem\" file",
					})
					return
				}
				domain := c.Param("domain")
				if domain == "" {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Parameter \"domain\" is missing",
					})
					return
				}
				err = certificatesApi.AddCustomCertificate(file, domain)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": err.Error(),
					})
					return
				}
				c.Status(http.StatusNoContent)
			})

			_ = r.DELETE("/certificates/:domain/custom", func(c *gin.Context) {
				domain := c.Param("domain")
				if domain == "" {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Parameter \"domain\" is missing",
					})
					return
				}
				err = certificatesApi.DeleteCustomCertificate(domain)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, err)
					return
				}
				c.Status(http.StatusNoContent)
			})
			_ = r.POST("/certificates", func(c *gin.Context) {
				var domains []string
				err := c.BindJSON(&domains)

				if err != nil {
					c.AbortWithError(http.StatusBadRequest, err)
					return
				}
				err = certificatesApi.ProvisionCertificates(o.LetsencryptMail, o.BundleCertificates, domains...)
				if err != nil {
					c.AbortWithError(http.StatusBadRequest, err)
					return
				}
				c.Status(http.StatusNoContent)

			})
			c := cron.New()
			//c.
			c.AddFunc("@daily", func() {
				err := certificatesApi.RenewCertificates(o.BundleCertificates)
				if err != nil {
					log.WithError(err).Println("Failed to renew certificates")
				} else {
					log.Println("Renewed certificates succesfully")
				}
			})
			go c.Start()

			err = certificatesApi.RenewCertificates(o.BundleCertificates)
			if err != nil {
				log.WithError(err).Println("Failed to renew certificates")
			} else {
				log.Println("Renewed certificates succesfully")
			}
			err = r.Run(":6000")
			if err != nil {
				return err
			}
			return nil
		},
	}
	flags := serveCmd.Flags()
	flags.StringVar(&o.HaproxyDir, "haproxy-dir", "", "Haproxy cfg path")
	flags.StringVar(&o.StorageDir, "storage-dir", "", "Folder to storage config and certificates")
	flags.StringVar(&o.LetsencryptMail, "le-mail", "", "Mail for let's encrypt")
	flags.BoolVar(&o.Staging, "le-staging", false, "Usae let's encrypt staging ca")
	flags.BoolVar(&o.BundleCertificates, "le-bundle", true, "Bundle issuer certificate and issued certificate")
	flags.StringVar(&o.StatsUser, "stats-user", "admin", "User for haproxy stats")
	flags.StringVar(&o.StatsPassword, "stats-password", "password", "Password for haproxy stats")
	flags.IntVar(&o.StatsPort, "stats-port", 9000, "Port for haproxy stats")

	serveCmd.MarkFlagRequired("haproxy-dir")
	serveCmd.MarkFlagRequired("storage-dir")
	serveCmd.MarkFlagRequired("le-mail")
	return serveCmd
}

type CertificatesApi struct {
	Options ServeOptions
	Config  *AcmeConfig
}

func NewCertificatesApi(o ServeOptions) (*CertificatesApi, error) {
	acmePath := filepath.Join(o.StorageDir, acmeJson)
	if _, err := os.Stat(acmePath); err != nil {
		// create file
		file, err := os.Create(acmePath)
		if err != nil {
			return nil, err
		}
		file.WriteString("{}")
		file.Close()
	}
	acmeContents, err := ioutil.ReadFile(acmePath)
	if err != nil {
		return nil, err
	}
	acmeConfig := &AcmeConfig{}
	err = json.Unmarshal(acmeContents, &acmeConfig)
	if err != nil {
		return nil, err
	}
	return &CertificatesApi{Options: o, Config: acmeConfig}, nil
}
func (c *CertificatesApi) getAcmePath() string {
	return filepath.Join(c.Options.StorageDir, acmeJson)
}

type AcmeUser struct {
	Email        string
	Key          []byte
	Certificates []*AcmeCertificate
}
type AcmeCertificate struct {
	Domain            string
	CertUrl           string
	CertStableUrl     string
	Key               []byte
	Crt               []byte
	Csr               []byte
	IssuerCertificate []byte
	AccountRef        string
}
type AcmeConfig struct {
	Accounts    []*AcmeUser
	CustomCerts []CustomCert
}

type CustomCert struct {
	Domain string
	Pem    []byte
}

type AcmeClient struct {
	Acme *acme.Client
	User *MyUser
}

func remove(s []string, i int) []string {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

func (c *CertificatesApi) RenewCertificate(email string, bundle bool, domains ...string) error {
	if len(domains) == 0 {
		return nil
	}
	acmeClient, err := c.getAcmeClient(email)
	if err != nil {
		return err
	}
	for idx := range c.Config.Accounts {
		user := c.Config.Accounts[idx]
		if user.Email != email {
			continue
		}
		for idxCrt := range user.Certificates {
			crt := c.Config.Accounts[idx].Certificates[idxCrt]
			for _, domain := range domains {
				if domain == crt.Domain {
					//  renew
					cert := acme.CertificateResource{
						Domain:            domain,
						Certificate:       crt.Crt,
						PrivateKey:        crt.Key,
						IssuerCertificate: crt.IssuerCertificate,
						CSR:               crt.Csr,
						CertURL:           crt.CertUrl,
						CertStableURL:     crt.CertStableUrl,
						AccountRef:        crt.AccountRef,
					}

					resource, err := acmeClient.Acme.RenewCertificate(cert, bundle, false)
					if err != nil {
						return err
					}
					crt.Domain = resource.Domain
					crt.Crt = resource.Certificate
					crt.Key = resource.PrivateKey
					crt.IssuerCertificate = resource.IssuerCertificate
					crt.Csr = resource.CSR
					crt.CertUrl = resource.CertURL
					crt.CertStableUrl = resource.CertStableURL
					crt.AccountRef = resource.AccountRef
				}
			}
		}
	}
	err = c.dumpCertificates()
	if err != nil {
		return errors.Wrapf(err, "Failed to dump certificates")
	}
	err = c.dumpAcmeJson()
	if err != nil {
		return errors.Wrapf(err, "Failed to dump config")
	}
	return reloadContainer(haproxyContainerName)
}
func (c *CertificatesApi) RenewCertificates(bundle bool) error {
	for _, acc := range c.Config.Accounts {
		for _, acmeCertificate := range acc.Certificates {
			block, _ := pem.Decode(acmeCertificate.Crt)
			if block == nil {
				panic("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				panic("failed to parse certificate: " + err.Error())
			}
			if cert.NotAfter.Before(time.Now().AddDate(0, 0, 10)) {
				log.Printf("Renewing certificate %s for email %s", acmeCertificate.Domain, acc.Email)
				err := c.RenewCertificate(acc.Email, bundle, acmeCertificate.Domain)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *CertificatesApi) IsCustomCertificate(domain string) bool {
	for _, customCrt := range c.Config.CustomCerts {
		if customCrt.Domain == domain {
			return true
		}
	}
	return false
}

func (c *CertificatesApi) ProvisionCertificates(email string, bundle bool, domains ...string) error {

	// remove certificates we have
	for _, acc := range c.Config.Accounts {
		if acc.Email == email {
			for _, certificate := range acc.Certificates {
				for i, domain := range domains {
					if certificate.Domain == domain {
						domains = remove(domains, i)
					}
				}

			}
		}
	}
	if len(domains) == 0 {
		return nil
	}
	acmeClient, err := c.getAcmeClient(email)
	if err != nil {
		return err
	}
	cr, err := acmeClient.Acme.ObtainCertificate(domains, bundle, nil, false)
	if err != nil {
		log.Printf("Error obtaining %v", err)
		return err
	}
	log.Debugf("Accounts %v", c.Config.Accounts)
	for idx := range c.Config.Accounts {
		user := c.Config.Accounts[idx]
		if user.Email != email {
			continue
		}
		for _, domain := range domains {
			certificate := &AcmeCertificate{
				Domain:            domain,
				Key:               cr.PrivateKey,
				CertUrl:           cr.CertURL,
				CertStableUrl:     cr.CertStableURL,
				Crt:               cr.Certificate,
				Csr:               cr.CSR,
				IssuerCertificate: cr.IssuerCertificate,
				AccountRef:        cr.AccountRef,
			}
			user.Certificates = append(user.Certificates, certificate)
		}
	}
	err = c.dumpCertificates()
	if err != nil {
		return errors.Wrapf(err, "Failed to dump certificates")
	}
	err = c.dumpAcmeJson()
	if err != nil {
		return errors.Wrapf(err, "Failed to dump config")
	}
	return reloadContainer(haproxyContainerName)
}

func (c *CertificatesApi) dumpCertificates() error {

	var err error

	crtListFile := filepath.Join(c.Options.HaproxyDir, crtListName)
	certsDir := filepath.Join(c.Options.HaproxyDir, "certs")
	err = os.MkdirAll(certsDir, os.ModePerm)
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	var certificates []*AcmeCertificate
	for _, account := range c.Config.Accounts {
		for _, certificate := range account.Certificates {
			certificates = append(certificates, certificate)
		}
	}
	for _, certificate := range certificates {
		domain := certificate.Domain
		externalCertFile := filepath.Join(certsDir, fmt.Sprintf("%s.pem", domain))
		buffer.WriteString(fmt.Sprintf("%s %s\n", externalCertFile, domain))
		fullChain := fmt.Sprintf("%s\n%s", string(certificate.Key), string(certificate.Crt))
		certFile := filepath.Join(certsDir, fmt.Sprintf("%s.pem", domain))
		err := ioutil.WriteFile(certFile, []byte(fullChain), os.ModePerm)
		if err != nil {
			return err
		}
	}
	for _, customCrt := range c.Config.CustomCerts {
		domain := customCrt.Domain
		externalCertFile := filepath.Join(certsDir, fmt.Sprintf("%s.pem", domain))
		buffer.WriteString(fmt.Sprintf("%s %s\n", externalCertFile, domain))
		certFile := filepath.Join(certsDir, fmt.Sprintf("%s.pem", domain))
		err := ioutil.WriteFile(certFile, customCrt.Pem, os.ModePerm)
		if err != nil {
			return err
		}
	}
	err = ioutil.WriteFile(crtListFile, buffer.Bytes(), os.ModePerm)
	if err != nil {
		return err
	}
	err = reloadContainer(haproxyContainerName)
	if err != nil {
		return err
	}
	return nil
}

func (c *CertificatesApi) getAcmeClient(email string) (*AcmeClient, error) {
	var myUser *MyUser
	for _, acc := range c.Config.Accounts {
		if acc.Email == email {
			privateKey, err := x509.ParsePKCS1PrivateKey(acc.Key)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to parse private Key")
			}
			myUser = &MyUser{
				Email: acc.Email,
				key:   privateKey,
			}
		}
	}
	if myUser == nil {
		log.Debugf("Creating acme account with email %s", email)
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		myUser = &MyUser{
			key:   privateKey,
			Email: email,
		}
		c.Config.Accounts = append(c.Config.Accounts, &AcmeUser{
			Email:        myUser.Email,
			Certificates: []*AcmeCertificate{},
			Key:          x509.MarshalPKCS1PrivateKey(privateKey),
		})
	}

	acmeClient, err := acme.NewClient(caDirUrl, myUser, acme.RSA2048)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to initialize acme client")
	}

	err = acmeClient.SetChallengeProvider(acme.HTTP01, le.NewHTTPProviderServer())
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set challenge http-01")
	}
	acmeClient.ExcludeChallenges([]acme.Challenge{acme.TLSALPN01, acme.DNS01})
	reg, err := acmeClient.Register(true)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to register acmeclient")
	}
	myUser.Registration = reg
	return &AcmeClient{Acme: acmeClient, User: myUser}, nil
}
func (c *CertificatesApi) dumpAcmeJson() error {
	contents, err := json.Marshal(c.Config)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(c.getAcmePath(), contents, os.ModePerm)

}

func (c *CertificatesApi) GetCertficates(email string) ([]*AcmeCertificate, error) {
	for _, acc := range c.Config.Accounts {
		if acc.Email == email {
			return acc.Certificates, nil
		}
	}
	return nil, errors.Errorf("The account with the email %s was not found", email)
}
func (c *CertificatesApi) GetCertficate(domain string) (*AcmeCertificate, error) {
	for _, acc := range c.Config.Accounts {
		for _, crt := range acc.Certificates {
			if crt.Domain == domain {
				return crt, nil
			}
		}
	}
	return nil, errors.Errorf("Certificate for domain %s not found", domain)
}

func (c *CertificatesApi) DeleteCustomCertificate(domain string) error {
	for i, customCrt := range c.Config.CustomCerts {
		if customCrt.Domain == domain {
			c.Config.CustomCerts[i] = c.Config.CustomCerts[len(c.Config.CustomCerts)-1]
			c.Config.CustomCerts = c.Config.CustomCerts[:len(c.Config.CustomCerts)-1]
			err := c.dumpCertificates()
			if err != nil {
				return errors.Wrapf(err, "Failed to dump certificates")
			}
			err = c.dumpAcmeJson()
			if err != nil {
				return errors.Wrapf(err, "Failed to dump config")
			}
			return reloadContainer(haproxyContainerName)
		}
	}
	return errors.Errorf("Custom certificate %s not found", domain)
}
func (c *CertificatesApi) AddCustomCertificate(file []byte, domain string) error {
	customCert := CustomCert{
		Domain: domain,
		Pem:    file,
	}
	for _, customCrt := range c.Config.CustomCerts {
		if customCrt.Domain == domain {
			return errors.Errorf("Custom certificate %s already exists", domain)
		}
	}
	c.Config.CustomCerts = append(c.Config.CustomCerts, customCert)
	err := c.dumpCertificates()
	if err != nil {
		return errors.Wrapf(err, "Failed to dump certificates")
	}
	err = c.dumpAcmeJson()
	if err != nil {
		return errors.Wrapf(err, "Failed to dump config")
	}
	return reloadContainer(haproxyContainerName)
}

type MyUser struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}
