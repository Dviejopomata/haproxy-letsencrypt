package types

type FrontendAddOptions struct {
	Name    string   `json:"name"`
	Mode    string   `json:"mode"`
	Port    int64    `json:"port"`
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
	If       string   `json:"if"`
	Frontend []string `json:"frontend"`
	Host     string   `json:"host"`
	Address  []string `json:"address"`
	Options  []string `json:"options"`
	Path     string   `json:"path"`
	Mode     string   `json:"mode"`
	Default  bool     `json:"default"`
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
	If      string
	Mode    string
	Host    string
	Path    string
	Servers []BackendServer
	Default bool
}

type BackendDeleteOptions struct {
	Frontend string
	Host     string `json:"host"`
	Path     string `json:"path"`
	Mode     string `json:"mode"`
}
