// Copyright (c) 2022 IndyKite
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugins

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/indykite/indykite-sdk-go/authorization"
	api "github.com/indykite/indykite-sdk-go/grpc"
	"github.com/indykite/indykite-sdk-go/grpc/config"
	"github.com/indykite/indykite-sdk-go/identity"
	json "github.com/json-iterator/go"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/logs"
	"github.com/open-policy-agent/opa/runtime"
	"github.com/sirupsen/logrus"
)

func init() {
	runtime.RegisterPlugin(PluginName, factory{})
}

var (
	lock          = sync.RWMutex{}
	defaultPlugin *IndyKitePlugin
)

// PluginName defines name of plugin used in config files.
const PluginName = "indykite_plugin"

type (
	// Config defines structure of plugin configuration.
	Config struct {
		credConfig *config.CredentialsConfig `yaml:"-"`

		Test            string `json:"test,omitempty" yaml:"test,omitempty"`
		UseEnvVariables bool   `json:"use_env_variables,omitempty" yaml:"use_env_variables,omitempty"`
	}

	factory struct{}

	// IndyKitePlugin defines internal structure of OPA Plugin.
	IndyKitePlugin struct {
		manager             *plugins.Manager
		config              *Config
		identityClient      *identity.Client
		authorizationClient *authorization.Client
		mtx                 sync.Mutex
	}
)

// IndyKite returns Plugin instance if it was defined in config, otherwise returns nil.
func IndyKite() *IndyKitePlugin {
	return defaultPlugin
}

func (factory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	return &IndyKitePlugin{
		manager: m,
		config:  config.(*Config),
	}
}

func (factory) Validate(_ *plugins.Manager, configData []byte) (interface{}, error) {
	parsedConfig := new(Config)
	err := json.Unmarshal(configData, parsedConfig)
	if err != nil {
		return nil, err
	}
	if parsedConfig.UseEnvVariables {
		return parsedConfig, nil
	}

	cfg := new(config.CredentialsConfig)

	// Take from the fastest config except precision and change the TagKey
	err = json.Config{
		EscapeHTML:                    false,
		ObjectFieldMustBeSimpleString: true,
		TagKey:                        "yaml",
	}.Froze().Unmarshal(configData, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Endpoint != "" {
		parsedConfig.credConfig = cfg
	}

	return parsedConfig, nil
}

// Start plugin based on its configuration.
func (p *IndyKitePlugin) Start(ctx context.Context) (err error) {
	var options []api.ClientOption
	if p.config.UseEnvVariables {
		options = append(options, api.WithCredentialsLoader(config.DefaultEnvironmentLoader))
	} else {
		options = append(options, api.WithCredentialsLoader(config.StaticCredentialConfig(p.config.credConfig)))
	}
	p.identityClient, err = identity.NewClient(ctx, options...)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"plugin": PluginName}).
			Info("failed to connect to IndyKite Identity client")
		return err
	}
	p.authorizationClient, err = authorization.NewClient(ctx, options...)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"plugin": PluginName}).
			Info("failed to connect to IndyKite Authorization client")
		return err
	}
	lock.Lock()
	defaultPlugin = p
	lock.Unlock()
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})
	return nil
}

// Stop plugin instance.
func (p *IndyKitePlugin) Stop(ctx context.Context) {
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

// Reconfigure internal plugin configuration state.
func (p *IndyKitePlugin) Reconfigure(ctx context.Context, config interface{}) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.config = config.(*Config)
}

// Log plugin events.
func (p *IndyKitePlugin) Log(ctx context.Context, event logs.EventV1) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	w := os.Stdout
	if _, err := fmt.Fprintln(w, event); err != nil {
		p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateErr})
	}
	return nil
}

// IdentityClient returns IndyKite identity client created from plugin configuration.
func (p *IndyKitePlugin) IdentityClient() *identity.Client {
	return p.identityClient
}

// AuthorizationClient returns IndyKite authorization client created from plugin configuration.
func (p *IndyKitePlugin) AuthorizationClient() *authorization.Client {
	return p.authorizationClient
}
