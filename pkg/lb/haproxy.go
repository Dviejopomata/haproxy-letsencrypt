package lb

import (
	"bytes"
	"fmt"
	"github.com/Dviejopomata/haproxy-letsencrypt/log"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/types"
	hatypes "github.com/Dviejopomata/haproxy-letsencrypt/pkg/types"
	"github.com/Masterminds/sprig"
	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"text/template"
)

type LoadBalancer interface {
	AddFrontend(options types.FrontendAddOptions) error
	AddBackend(options types.BackendAddOptions) error
	Dump() (string, error)
}

type HaproxyLb struct {
	LeContents []byte
	config     *HaproxyConfig
}

func (h *HaproxyLb) AddFrontend(options types.FrontendAddOptions) error {
	for i, frontend := range h.config.Frontends {
		if frontend.Name == options.Name {
			h.config.Frontends[i] = hatypes.Frontend{
				Name:     options.Name,
				Port:     options.Port,
				Ssl:      options.Ssl,
				Options:  options.Options,
				Mode:     options.Mode,
				Backends: frontend.Backends,
				Lines:    options.Lines,
			}
			return nil
		}
	}
	h.config.Frontends = append(h.config.Frontends, hatypes.Frontend{
		Name:     options.Name,
		Port:     options.Port,
		Ssl:      options.Ssl,
		Options:  options.Options,
		Mode:     options.Mode,
		Backends: []hatypes.Backend{},
		Lines:    options.Lines,
	})
	return nil
}

func (h *HaproxyLb) AddBackend(options types.BackendAddOptions) error {
	for _, fe := range options.Frontend {
	OUTER:
		for idx := range h.config.Frontends {
			frontend := &h.config.Frontends[idx]
			if fe == frontend.Name {
				var servers []hatypes.BackendServer
				for i, address := range options.Address {
					serverOptions := ""
					if i < len(options.Options) {
						serverOptions = options.Options[i]
					}
					servers = append(servers, hatypes.BackendServer{Address: address, Options: serverOptions})
				}
				if options.Default {
					for idx := range frontend.Backends {
						frontend.Backends[idx].Default = false
					}
				}
				for i, be := range frontend.Backends {
					if be.Host == options.Host && be.Mode == options.Mode && be.Path == options.Path {
						frontend.Backends[i] = hatypes.Backend{
							If:      options.If,
							Host:    options.Host,
							Mode:    options.Mode,
							Servers: servers,
							Default: options.Default,
							Path:    options.Path,
						}
						continue OUTER
					}
				}

				backend := hatypes.Backend{
					If:      options.If,
					Host:    options.Host,
					Mode:    options.Mode,
					Servers: servers,
					Default: options.Default,
					Path:    options.Path,
				}

				frontend.Backends = append(frontend.Backends, backend)
			}
		}
	}

	return nil
}
func (h *HaproxyLb) GetFrontends() []hatypes.Frontend {
	return h.config.Frontends
}
func (h *HaproxyLb) GetFrontend(name string) (hatypes.Frontend, error) {
	for _, frontend := range h.config.Frontends {
		if frontend.Name == name {
			return frontend, nil
		}
	}
	return hatypes.Frontend{}, errors.Errorf("Frontend %s not found", name)
}
func (h *HaproxyLb) DeleteBackend(options types.BackendDeleteOptions) error {

	for i, fe := range h.config.Frontends {
		if fe.Name == options.Frontend {
			for j, backend := range fe.Backends {
				if options.Path == backend.Path &&
					options.Host == backend.Host &&
					options.Mode == backend.Mode {
					h.config.Frontends[i].Backends = append(h.config.Frontends[i].Backends[:j], h.config.Frontends[i].Backends[j+1:]...)
					return nil

				}
			}
		}

	}
	return errors.Errorf("Backend not found: %v", options)
}
func NewHaproxyLb(leContents []byte) (*HaproxyLb, error) {
	haproxyLb := &HaproxyLb{
		LeContents: leContents,
		config:     &HaproxyConfig{},
	}
	err := haproxyLb.parseConfig()
	if err != nil {
		return nil, err
	}
	return haproxyLb, nil
}

func (h *HaproxyLb) parseConfig() error {
	var err error
	h.config = &HaproxyConfig{}

	err = yaml.Unmarshal(h.LeContents, h.config)
	if err != nil {
		return err
	}
	if err := mergo.Merge(h.config, getDefaultConfig()); err != nil {
		return err
	}
	return nil
}
func getDefaultConfig() *HaproxyConfig {
	return &HaproxyConfig{
		Frontends: []hatypes.Frontend{},
	}
}

type HaproxyConfig struct {
	Frontends          []hatypes.Frontend
	Letsencryptaddress string
}
type ComputedBackend struct {
	Name    string
	Mode    string
	Lines   []string
	Servers []ComputedServer
}
type ComputedServer struct {
	Mode  string
	Lines []string
}
type ComputedFrontend struct {
	Name     string
	Lines    []string
	Backends []ComputedBackend
}
type ComputedHaproxyConfig struct {
	Frontends []ComputedFrontend
}
type BufferNewLine struct {
	bytes.Buffer
}

func (b *BufferNewLine) WriteNewLine(str string) (n int, err error) {
	return b.WriteString(fmt.Sprintf("%s\n", str))
}

func computeConfig(config HaproxyConfig) ComputedHaproxyConfig {
	finalConfig := ComputedHaproxyConfig{}
	for _, frontend := range config.Frontends {
		var buffer BufferNewLine
		if len(frontend.Backends) == 0 {
			continue
		}
		if frontend.Ssl {
			buffer.WriteNewLine(fmt.Sprintf("bind *:%d ssl crt-list /usr/local/etc/haproxy/crt-list.txt %s", frontend.Port, frontend.Options))
		} else {
			buffer.WriteNewLine(fmt.Sprintf("bind *:%d %s", frontend.Port, frontend.Options))
		}
		buffer.WriteNewLine(fmt.Sprintf("mode %s", frontend.Mode))
		for _, line := range frontend.Lines {
			buffer.WriteNewLine(line)
		}
		var backends []ComputedBackend
		for backendIdx, backend := range frontend.Backends {
			backendName := fmt.Sprintf("be_%s_%d_%s", frontend.Name, backendIdx, backend.Host)
			if backend.Default {
				buffer.WriteNewLine(fmt.Sprintf("default_backend %s", backendName))
			}
			var backendLines BufferNewLine
			for _, server := range backend.Servers {
				backendLines.WriteNewLine(fmt.Sprintf("server main %s %s", server.Address, server.Options))
			}
			var backendIf bytes.Buffer
			if backend.If != "" {
				backendIf.WriteString(backend.If)
			} else {
				if backend.Host != "" {
					backendIf.WriteString(fmt.Sprintf("hdr(host) -i %s  ", backend.Host))
				}
				if backend.Path != "" {
					backendIf.WriteString(fmt.Sprintf("  path_beg %s", backend.Path))
				}
			}
			if backendIf.Len() > 0 {
				buffer.WriteNewLine(fmt.Sprintf("use_backend %s if { %s }", backendName, backendIf.String()))
			}
			backends = append(backends, ComputedBackend{
				Name:  backendName,
				Mode:  backend.Mode,
				Lines: []string{backendLines.String()},
			})
		}

		finalConfig.Frontends = append(finalConfig.Frontends, ComputedFrontend{
			Backends: backends,
			Name:     frontend.Name,
			Lines:    []string{buffer.String()},
		})
	}
	if len(finalConfig.Frontends) == 0 {
		finalConfig.Frontends = append(finalConfig.Frontends, ComputedFrontend{
			Name: "http",
			Lines: []string{
				"bind *:80",
				"mode http",
			},
		})
	}
	return finalConfig

}

const haproxyTemplate string = `
global
  # log /dev/log    local0
  # log /dev/log    local1 notice
  # chroot /var/lib/haproxy
  # stats socket /run/haproxy/admin.sock mode 660 level admin
  # stats timeout 30s
  user nobody
  daemon
  # Default ciphers to use on SSL-enabled listening sockets.
  # For more information, see ciphers(1SSL). This list is from:
  #  https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
  ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS
  ssl-default-bind-options no-sslv3

defaults
  maxconn 1000
  mode http
  log global
  option dontlognull # bind *:443 ssl crt .
  timeout http-request 5s
  timeout connect 5000
  timeout client 2000000
  timeout server 2000000

# this load balancer servers both www.site.com and static.site.com, but those two URLS have
# different servers on the backend (app servers versus statis media apache instances)
# also, I want to server www.site.com/static/* from the later farm
{{ range $frontend := .Frontends}}
frontend {{ $frontend.Name }}
	{{ range $line := $frontend.Lines -}} 
  		{{$line | indent 2}} 
	{{ end -}} 

{{- range $backend := $frontend.Backends }}
backend {{ $backend.Name }}
  mode {{ $backend.Mode }}
	{{ range $line := $backend.Lines -}}
  		{{ $line | indent 2 }}
	{{ end -}}

{{- end -}}

{{- end }}

`

type DumpResponse struct {
	YamlConfig    string
	HaproxyConfig string
}

func (h *HaproxyLb) Dump() (dumpResponse DumpResponse, err error) {
	yamlBytes, err := yaml.Marshal(h.config)
	if err != nil {
		return
	}

	tmpl, err := template.New("test").Funcs(sprig.TxtFuncMap()).Parse(haproxyTemplate)
	if err != nil {
		return
	}
	var b bytes.Buffer
	err = tmpl.Execute(&b, computeConfig(*h.config))
	if err != nil {
		return
	}
	log.Debugf("Haproxy cfg", b.String())
	dumpResponse = DumpResponse{
		HaproxyConfig: string(b.String()),
		YamlConfig:    string(yamlBytes),
	}
	return
}
func (h *HaproxyLb) DeleteFrontend(options types.FrontendDeleteOptions) error {
	for i, fe := range h.config.Frontends {
		if fe.Name == options.Name {
			h.config.Frontends = append(h.config.Frontends[:i], h.config.Frontends[i+1:]...)
			return nil
		}
	}
	return errors.Errorf("Frontend %s not found", options.Name)
}