package lb

import (
	"bytes"
	"github.com/Dviejopomata/haproxy-letsencrypt/pkg/types"
	"gopkg.in/yaml.v2"
	"testing"
)

func mergeWithDefaultConfig(config HaproxyConfig) *HaproxyConfig {
	//defaultConfig := getDefaultConfig()
	//feArr := map[string]types.Frontend{}
	//for _, fe := range config.Frontends {
	//	feArr[fe.Name] = fe
	//}
	//_, hasHttpFrontend := feArr["http"]
	//_, hasHttpsFrontend := feArr["https"]
	//if !hasHttpFrontend || (!hasHttpFrontend && hasHttpsFrontend) {
	//	if !hasHttpsFrontend {
	//		config.Frontends = append([]types.Frontend{defaultConfig.Frontends[1]}, config.Frontends...)
	//	}
	//	config.Frontends = append([]types.Frontend{defaultConfig.Frontends[0]}, config.Frontends...)
	//} else if hasHttpFrontend && !hasHttpsFrontend {
	//	config.Frontends = append(config.Frontends, defaultConfig.Frontends[1])
	//} else {
	//	for i := len(defaultConfig.Frontends) - 1; i >= 0; i-- {
	//		fe := defaultConfig.Frontends[i]
	//		if _, ok := feArr[fe.Name]; !ok {
	//			config.Frontends = append([]types.Frontend{fe}, config.Frontends...)
	//		}
	//	}
	//}
	return &config
}

func TestHaproxyLb(t *testing.T) {
	testCases := map[string]struct {
		BackendOptions  []types.BackendAddOptions
		FrontendOptions []types.FrontendAddOptions
		Expected        *HaproxyConfig
	}{
		"empty": {
			Expected:        getDefaultConfig(),
			FrontendOptions: []types.FrontendAddOptions{},
			BackendOptions:  []types.BackendAddOptions{},
		},
		"Simple frontend and backend": {
			Expected: &HaproxyConfig{
				Frontends: []types.Frontend{
					{
						Name: "http",
						Mode: "http",
						Backends: []types.Backend{
							{
								Mode: "http",
								Host: "example.org",
								Servers: []types.BackendServer{
									{
										Address: "192.168.1.47:9000",
									},
								},
							},
						},
						Port: 80,
					},
				},
			},
			FrontendOptions: []types.FrontendAddOptions{
				{
					Name: "http",
					Port: 80,
					Mode: "http",
				},
			},
			BackendOptions: []types.BackendAddOptions{
				{
					Mode:     "http",
					Address:  []string{"192.168.1.47:9000"},
					Host:     "example.org",
					Frontend: []string{"http"},
				},
			},
		},
		"Ssh": {
			Expected: mergeWithDefaultConfig(HaproxyConfig{
				Frontends: []types.Frontend{
					{
						Ssl:     false,
						Mode:    "tcp",
						Name:    "ssh",
						Options: "",
						Port:    10222,
						Backends: []types.Backend{
							{
								Mode:    "tcp",
								Default: true,
								Servers: []types.BackendServer{
									{
										Address: "127.0.0.1:22222",
									},
								},
							},
						},
					},
				},
			}),
			BackendOptions: []types.BackendAddOptions{
				{
					Mode:     "tcp",
					Address:  []string{"127.0.0.1:22222"},
					Default:  true,
					Frontend: []string{"ssh"},
				},
			},
			FrontendOptions: []types.FrontendAddOptions{
				{
					Mode: "tcp",
					Name: "ssh",
					Port: 10222,
					Ssl:  false,
				},
			},
		},
	}
	for tcName, tc := range testCases {
		config := &HaproxyConfig{}
		yamlContents, err := yaml.Marshal(config)
		if err != nil {
			t.Fatalf("Error converting yaml to string: %v", err)
		}
		haproxyLb, err := NewHaproxyLb(yamlContents)
		if err != nil {
			t.Fatalf("Error initializing haproxy lb: %v", err)
		}

		for _, frontendOptions := range tc.FrontendOptions {
			err := haproxyLb.AddFrontend(frontendOptions)
			if err != nil {
				t.Fatalf("Error adding frontend: %v", err)
			}
		}
		for _, backendOptions := range tc.BackendOptions {
			err := haproxyLb.AddBackend(backendOptions)
			if err != nil {
				t.Fatalf("Error adding backend: %v", err)
			}
		}

		bytes1, err := yaml.Marshal(tc.Expected)
		if err != nil {
			t.Fatalf("Failed to marshall expected config: %v", err)
		}
		bytes2, err := yaml.Marshal(haproxyLb.config)
		if err != nil {
			t.Fatalf("Failed to marshall current config: %v", err)
		}
		if !bytes.Equal(bytes1, bytes2) {
			t.Errorf("test %s failed, expected \n%s \ngot \n%s", tcName, string(bytes1), string(bytes2))
		} else {
			//log.Printf("\n%s", string(bytes1))
			//log.Printf("\n%s", string(bytes2))
		}
	}
}
