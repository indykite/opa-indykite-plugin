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

package functions

import (
	"context"
	"sync"

	api "github.com/indykite/jarvis-sdk-go/grpc"
	"github.com/indykite/jarvis-sdk-go/grpc/config"
	"github.com/indykite/jarvis-sdk-go/identity"
	"github.com/sirupsen/logrus"

	"github.com/indykite/opa-indykite-plugin/plugins"
)

var (
	clientConn *identity.Client
	clientMtx  sync.Mutex
)

// OverrideClient set and override Client Connection for OPA and return previously set connection.
func OverrideClient(conn *identity.Client) *identity.Client {
	oldConn := clientConn
	clientConn = conn
	return oldConn
}

// Client creates IndyKite Identity client based on defined plugin or environment variables.
func Client(ctx context.Context) (*identity.Client, error) {
	if clientConn != nil {
		return clientConn, nil
	}

	clientMtx.Lock()
	defer clientMtx.Unlock()

	if plugin := plugins.IndyKite(); plugin != nil {
		clientConn = plugin.Client()
	} else {
		c, err := identity.NewClient(ctx, api.WithCredentialsLoader(config.DefaultEnvironmentLoader))
		if err != nil {
			logrus.WithError(err).Info("failed to connect to IndyKite")
			return nil, err
		}
		clientConn = c
	}

	return clientConn, nil
}
