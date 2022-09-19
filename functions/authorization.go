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
	identity "github.com/indykite/jarvis-sdk-go/gen/indykite/identity/v1beta1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/pborman/uuid"

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
			req := &identity.IsAuthorizedRequest{}

			req.Subject, err = extractDigitalTwinIdentifier(dtIdentifier.Value, 1)
			if err != nil {
				return nil, err
			}
			if err = ast.As(actions.Value, &req.Actions); err != nil {
				return nil, err
			}
			if err = ast.As(resourceRefs.Value, &req.Resources); err != nil {
				return nil, err
			}

			client, err := Client(bCtx.Context)
			if err != nil {
				return nil, err
			}
			var resp *identity.IsAuthorizedResponse
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

func extractDigitalTwinIdentifier(identifierValue ast.Value, pos int) (*identity.DigitalTwinIdentifier, error) {
	switch identifier := identifierValue.(type) {
	case ast.String:
		return &identity.DigitalTwinIdentifier{Filter: &identity.DigitalTwinIdentifier_AccessToken{
			AccessToken: string(identifier),
		}}, nil
	case ast.Object:
		var dtID, tenantID uuid.UUID
		var err error

		dtID, err = utilities.ParseTermAsUUID(identifier.Get(ast.StringTerm("digital_twin_id")))
		if err != nil {
			return nil, builtins.NewOperandErr(pos, "digital_twin_id: "+err.Error())
		}
		tenantID, err = utilities.ParseTermAsUUID(identifier.Get(ast.StringTerm("tenant_id")))
		if err != nil {
			return nil, builtins.NewOperandErr(pos, "tenant_id: "+err.Error())
		}
		return &identity.DigitalTwinIdentifier{Filter: &identity.DigitalTwinIdentifier_DigitalTwin{
			DigitalTwin: &identity.DigitalTwin{Id: dtID, TenantId: tenantID},
		}}, nil
	}
	// Next line is unreachable. OPA will complain based on declaration of function, when types do not match.
	return nil, builtins.NewOperandTypeErr(pos, identifierValue, "string", "object")
}

func buildIsAuthorizedObjectFromResponse(resp *identity.IsAuthorizedResponse) ast.Object {
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
