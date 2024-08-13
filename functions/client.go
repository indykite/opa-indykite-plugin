// Copyright (c) 2023 IndyKite
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

	"github.com/indykite/indykite-sdk-go/authorization"
	api "github.com/indykite/indykite-sdk-go/grpc"
	"github.com/indykite/indykite-sdk-go/grpc/config"
	"github.com/sirupsen/logrus"

	"github.com/indykite/opa-indykite-plugin/plugins"
)

var (
	authorizationClient *authorization.Client
	clientMtx           sync.Mutex
)

// OverrideAuthorizationClient set and override AuthorizationClient Connection for OPA and return previously
// set connection.
func OverrideAuthorizationClient(conn *authorization.Client) *authorization.Client {
	oldConn := authorizationClient
	authorizationClient = conn
	return oldConn
}

// AuthorizationClient creates IndyKite Authorization client based on defined plugin or environment variables.
func AuthorizationClient(ctx context.Context) (*authorization.Client, error) {
	if authorizationClient != nil {
		return authorizationClient, nil
	}

	clientMtx.Lock()
	defer clientMtx.Unlock()

	if plugin := plugins.IndyKite(); plugin != nil {
		authorizationClient = plugin.AuthorizationClient()
	} else {
		c, err := authorization.NewClient(ctx, api.WithCredentialsLoader(config.DefaultEnvironmentLoader))
		if err != nil {
			logrus.WithError(err).Info("failed to connect to IndyKite")
			return nil, err
		}
		authorizationClient = c
	}

	return authorizationClient, nil
}
