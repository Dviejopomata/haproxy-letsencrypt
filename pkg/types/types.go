package types

type FrontendAddOptions struct {
	Name    string   `json:"name"`
	Mode    string   `json:"mode"`
	Port    int64    `json:"port"`
	Bind    string   `json:"bind"`
	Lines   []string `json:"lines"`
	Ssl     bool     `json:"ssl"`
	Options string   `json:"options"`
}
type FrontendListOptions struct{}
type FrontendListOptionsResponse struct {
	Frontends []Frontend
}

type FrontendDeleteOptions struct {
	Name string
}

type BackendAddOptions struct {
	If                   string   `json:"if"`
	Frontend             []string `json:"frontend"`
	Host                 string   `json:"host"`
	Sni                  string   `json:"sni"`
	Address              []string `json:"address"`
	Options              []string `json:"options"`
	Path                 string   `json:"path"`
	Mode                 string   `json:"mode"`
	Default              bool     `json:"default"`
	BasicAuth            []string `json:"basic_auth"`
	ProvisionCertificate bool     `json:"provision_certificate"`
}
type BackendListOptionsResponse struct {
	Frontend Frontend `json:"frontend"`
}
type BackendListOptions struct {
	Frontend string `json:"frontend"`
}

type Frontend struct {
	Name     string    `json:"name"`
	Port     int64     `json:"port"`
	Bind     string    `json:"bind"`
	Mode     string    `json:"mode"`
	Lines    []string  `json:"lines"`
	Backends []Backend `json:"backends"`
	Options  string    `json:"options"`
	Ssl      bool      `json:"ssl"`
}

type BackendServer struct {
	Address string
	Options string
}

type Backend struct {
	If        string
	Mode      string
	Host      string
	Sni       string
	Path      string
	Servers   []BackendServer
	Default   bool
	BasicAuth []string
}

type BackendDeleteOptions struct {
	Frontend string
	Host     string `json:"host"`
	Sni      string `json:"sni"`
	Path     string `json:"path"`
	Mode     string `json:"mode"`
}
