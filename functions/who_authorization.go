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
	"bytes"

	"github.com/indykite/indykite-sdk-go/errors"
	authorizationpb "github.com/indykite/indykite-sdk-go/gen/indykite/authorization/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/indykite/opa-indykite-plugin/utilities"
)

func init() {
	rego.RegisterBuiltin3(
		&rego.Function{
			Name: "indy.who_authorized",
			Decl: types.NewFunction(
				types.Args(
					types.Named("resources", types.NewArray(nil, types.NewObject([]*types.StaticProperty{
						types.NewStaticProperty("externalId", types.S),
						types.NewStaticProperty("type", types.S),
						types.NewStaticProperty("actions", types.NewArray(nil, types.S)),
					}, nil))),
					types.Named(inputParamsKey, types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
					types.Named(policyTagsKey, types.NewArray(nil, types.S)),
				),
				types.Named("authorizationResponse", types.NewObject([]*types.StaticProperty{
					types.NewStaticProperty("decisionTime", types.N),
					types.NewStaticProperty("decisions", types.NewObject(nil, types.NewDynamicProperty(
						types.S,
						types.NewObject(nil, types.NewDynamicProperty(
							types.S,
							types.NewObject(nil, types.NewDynamicProperty(
								types.S,
								types.NewObject([]*types.StaticProperty{
									types.NewStaticProperty("externalId", types.B),
								}, nil),
							)),
						)),
					))),
				}, nil)),
			),
		},
		func(bCtx rego.BuiltinContext, resources, inputParams, policyTags *ast.Term) (*ast.Term, error) {
			var (
				err error
				req = &authorizationpb.WhoAuthorizedRequest{}
			)

			req.Resources, err = parseWhoResources(resources, 1)
			if err != nil {
				return nil, err
			}

			req.InputParams, err = utilities.ParseInputParams(inputParams, 2)
			if err != nil {
				return nil, err
			}

			req.PolicyTags = parsePolicyTags(policyTags)

			client, err := AuthorizationClient(bCtx.Context)
			if err != nil {
				return nil, err
			}

			var (
				resp *authorizationpb.WhoAuthorizedResponse
				obj  ast.Object
			)
			resp, err = client.WhoAuthorized(bCtx.Context, req)
			if statusErr := errors.FromError(err); statusErr != nil {
				if errors.IsServiceError(statusErr) {
					return nil, statusErr
				}
				obj = ast.NewObject(ast.Item(ast.StringTerm("error"), utilities.BuildUserError(statusErr)))
			} else {
				obj = buildWhoAuthorizedObjectFromResponse(resp)
			}

			return &ast.Term{Value: obj}, nil
		},
	)
}

func buildWhoAuthorizedObjectFromResponse(resp *authorizationpb.WhoAuthorizedResponse) ast.Object {
	decisions := ast.NewObject()

	for resourceType, dec := range resp.Decisions {
		resources := ast.NewObject()
		for resourceKey, resourceValue := range dec.Resources {
			actions := ast.NewObject()
			for actionKey, actionValue := range resourceValue.Actions {
				subjects := ast.NewArray()
				for _, s := range actionValue.Subjects {
					subject := ast.NewTerm(ast.NewObject(
						ast.Item(ast.StringTerm("externalId"), ast.StringTerm(s.ExternalId)),
					))
					subjects = subjects.Append(subject)
				}
				actions.Insert(ast.StringTerm(actionKey), ast.NewTerm(subjects))
			}
			resources.Insert(ast.StringTerm(resourceKey), ast.NewTerm(actions))
		}
		decisions.Insert(ast.StringTerm(resourceType), ast.NewTerm(resources))
	}

	obj := ast.NewObject(
		ast.Item(ast.StringTerm("error"), ast.NullTerm()),
		ast.Item(ast.StringTerm("decisionTime"), ast.IntNumberTerm(int(resp.DecisionTime.AsTime().Unix()))),
		ast.Item(ast.StringTerm("decisions"), ast.NewTerm(decisions)),
	)

	return obj
}

func parseWhoResources(term *ast.Term, pos int) ([]*authorizationpb.WhoAuthorizedRequest_Resource, error) {
	resources, err := builtins.ArrayOperand(term.Value, pos)
	if err != nil {
		return nil, err
	}
	resp := make([]*authorizationpb.WhoAuthorizedRequest_Resource, resources.Len())
	for i := 0; i < resources.Len(); i++ {
		e := resources.Elem(i)
		if v, ok := e.Value.(ast.Object); ok {
			var res = &authorizationpb.WhoAuthorizedRequest_Resource{}
			if err = protojson.Unmarshal(bytes.NewBufferString(v.String()).Bytes(), res); err != nil {
				return nil, err
			}
			resp[i] = res
		}
	}
	return resp, nil
}
