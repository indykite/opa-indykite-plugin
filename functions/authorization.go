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
	"github.com/indykite/jarvis-sdk-go/errors"
	authorizationpb "github.com/indykite/jarvis-sdk-go/gen/indykite/authorization/v1beta1"
	identitypb "github.com/indykite/jarvis-sdk-go/gen/indykite/identity/v1beta2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"

	"github.com/indykite/opa-indykite-plugin/utilities"
)

func init() {
	rego.RegisterBuiltin3(
		&rego.Function{
			Name: "indy.is_authorized",
			Decl: types.NewFunction(
				types.Args(
					types.Named("digital_twin_identifier", types.NewAny(
						types.S,
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("digital_twin_id", types.S),
							types.NewStaticProperty("tenant_id", types.S),
						}, nil),
					)),
					types.Named("actions", types.NewArray(nil, types.S)),
					types.Named("resources", types.NewArray(nil, types.NewObject([]*types.StaticProperty{
						types.NewStaticProperty("id", types.S),
						types.NewStaticProperty("label", types.S),
					}, nil))),
				),
				types.Named("authorization_decisions", types.NewObject([]*types.StaticProperty{
					types.NewStaticProperty("decision_time", types.N),
					types.NewStaticProperty("decisions", types.NewObject(nil, types.NewDynamicProperty(
						types.S,
						types.NewObject([]*types.StaticProperty{
							types.NewStaticProperty("allow_action", types.NewObject(nil, types.NewDynamicProperty(
								types.S,
								types.B,
							))),
						}, nil),
					))),
				}, nil)),
			),
		},
		func(bCtx rego.BuiltinContext, dtIdentifier, actions, resourceRefs *ast.Term) (*ast.Term, error) {
			var err error
			req := &authorizationpb.IsAuthorizedRequest{}

			digitalTwinIdentifier, err := extractDigitalTwinIdentifier(dtIdentifier.Value, 1)
			if err != nil {
				return nil, err
			}
			if err = ast.As(actions.Value, &req.Actions); err != nil {
				return nil, err
			}
			if err = ast.As(resourceRefs.Value, &req.Resources); err != nil {
				return nil, err
			}

			req.Subject = &authorizationpb.IsAuthorizedRequest_DigitalTwinIdentifier{
				DigitalTwinIdentifier: digitalTwinIdentifier,
			}

			client, err := AuthorizationClient(bCtx.Context)
			if err != nil {
				return nil, err
			}
			var resp *authorizationpb.IsAuthorizedResponse
			resp, err = client.IsAuthorizedWithRawRequest(bCtx.Context, req)
			var obj ast.Object

			if statusErr := errors.FromError(err); statusErr != nil {
				if errors.IsServiceError(statusErr) {
					return nil, statusErr
				}
				obj = ast.NewObject(ast.Item(ast.StringTerm("error"), utilities.BuildUserError(statusErr)))
			} else {
				obj = buildIsAuthorizedObjectFromResponse(resp)
			}

			return &ast.Term{Value: obj}, nil
		},
	)
}

func extractDigitalTwinIdentifier(identifierValue ast.Value, pos int) (*identitypb.DigitalTwinIdentifier, error) {
	switch identifier := identifierValue.(type) {
	case ast.String:
		return &identitypb.DigitalTwinIdentifier{Filter: &identitypb.DigitalTwinIdentifier_AccessToken{
			AccessToken: string(identifier),
		}}, nil
	case ast.Object:
		var dtID, tenantID ast.String

		dtID = identifier.Get(ast.StringTerm("digital_twin_id")).Value.(ast.String)
		tenantID = identifier.Get(ast.StringTerm("tenant_id")).Value.(ast.String)

		return &identitypb.DigitalTwinIdentifier{Filter: &identitypb.DigitalTwinIdentifier_DigitalTwin{
			DigitalTwin: &identitypb.DigitalTwin{Id: string(dtID), TenantId: string(tenantID)},
		}}, nil
	}
	// Next line is unreachable. OPA will complain based on declaration of function, when types do not match.
	return nil, builtins.NewOperandTypeErr(pos, identifierValue, "string", "object")
}

func buildIsAuthorizedObjectFromResponse(resp *authorizationpb.IsAuthorizedResponse) ast.Object {
	decisions := ast.NewObject()

	for resRef, dec := range resp.Decisions {
		allowAction := ast.NewObject()
		for k, v := range dec.AllowAction {
			allowAction.Insert(ast.StringTerm(k), ast.BooleanTerm(v))
		}

		decisions.Insert(ast.StringTerm(resRef), ast.NewTerm(ast.NewObject(
			ast.Item(ast.StringTerm("allow_actions"), ast.NewTerm(allowAction)),
		)))
	}

	obj := ast.NewObject(
		ast.Item(ast.StringTerm("error"), ast.NullTerm()),
		ast.Item(ast.StringTerm("decision_time"), ast.IntNumberTerm(int(resp.DecisionTime.AsTime().Unix()))),
		ast.Item(ast.StringTerm("decisions"), ast.NewTerm(decisions)),
	)

	return obj
}
