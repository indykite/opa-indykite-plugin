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
	"time"

	"github.com/indykite/indykite-sdk-go/errors"
	identity "github.com/indykite/indykite-sdk-go/gen/indykite/identity/v1beta2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"github.com/indykite/opa-indykite-plugin/utilities"
)

func init() {
	rego.RegisterBuiltin2(
		&rego.Function{
			Name:    "indy.identity_properties",
			Decl:    types.NewFunction(types.Args(types.S, types.NewArray(nil, types.S)), types.A),
			Memoize: true,
		},
		func(bCtx rego.BuiltinContext, tokenTerm, propsTerm *ast.Term) (*ast.Term, error) {
			var token string
			var properties []string
			var err error

			if err = ast.As(tokenTerm.Value, &token); err != nil {
				return nil, err
			}
			if err = ast.As(propsTerm.Value, &properties); err != nil {
				return nil, err
			}

			client, err := IdentityClient(bCtx.Context)
			if err != nil {
				return nil, err
			}
			propMasks := []*identity.PropertyMask{}
			for _, v := range properties {
				propMasks = append(propMasks, &identity.PropertyMask{Definition: &identity.PropertyDefinition{
					Property: v,
				}})
			}
			resp, err := client.GetDigitalTwinByToken(bCtx.Context, token, propMasks)
			var obj ast.Object

			if statusErr := errors.FromError(err); statusErr != nil {
				if errors.IsServiceError(statusErr) {
					return nil, statusErr
				}
				obj = ast.NewObject(ast.Item(ast.StringTerm("error"), utilities.BuildUserError(statusErr)))
			} else {
				obj, err = buildDigitalTwinPropertiesObject(resp)
				if err != nil {
					return nil, err
				}
			}

			return &ast.Term{Value: obj}, nil
		},
	)
}

func buildDigitalTwinPropertiesObject(resp *identity.GetDigitalTwinResponse) (ast.Object, error) {
	tokenInfo := ast.NewObject()
	if ti := resp.GetTokenInfo(); ti != nil {
		if err := fillAstWithTokenInfo(tokenInfo, ti); err != nil {
			return nil, err
		}
		tokenInfo.Insert(ast.StringTerm("active"), ast.BooleanTerm(true))
	}
	properties := ast.NewArray()
	for _, prop := range resp.GetDigitalTwin().GetProperties() {
		astProp, err := buildPropertyObject(prop)
		if err != nil {
			return nil, err
		}
		properties = properties.Append(&ast.Term{Value: astProp})
	}

	obj := ast.NewObject(
		ast.Item(ast.StringTerm("error"), ast.NullTerm()),
		ast.Item(ast.StringTerm("token_info"), ast.NewTerm(tokenInfo)),
		ast.Item(ast.StringTerm("properties"), ast.NewTerm(properties)),
	)

	return obj, nil
}

func buildPropertyObject(prop *identity.Property) (ast.Object, error) {
	definition := ast.NewObject(
		ast.Item(ast.StringTerm("context"), ast.StringTerm(prop.GetDefinition().GetContext())),
		ast.Item(ast.StringTerm("property"), ast.StringTerm(prop.GetDefinition().GetProperty())),
		ast.Item(ast.StringTerm("type"), ast.StringTerm(prop.GetDefinition().GetType())),
	)
	meta := ast.NewObject(
		ast.Item(ast.StringTerm("assuranceLevel"), ast.IntNumberTerm(int(prop.GetMeta().GetAssuranceLevel()))),
		ast.Item(ast.StringTerm("issuer"), ast.StringTerm(prop.GetMeta().GetIssuer())),
		ast.Item(ast.StringTerm("primary"), ast.BooleanTerm(prop.GetMeta().GetPrimary())),
		ast.Item(ast.StringTerm("verifier"), ast.StringTerm(prop.GetMeta().GetVerifier())),
	)
	astVfTime := ast.NullTerm()
	if vft := prop.GetMeta().GetVerificationTime(); vft != nil {
		astVfTime = ast.StringTerm(vft.AsTime().Format(time.RFC3339))
	}
	meta.Insert(ast.StringTerm("verificationTime"), astVfTime)

	astValue, err := utilities.ObjectsValueIntoAstTerm(prop.GetObjectValue())
	if err != nil {
		return nil, err
	}

	astProp := ast.NewObject(
		ast.Item(ast.StringTerm("id"), ast.NewTerm(ast.String(prop.Id))),
		ast.Item(ast.StringTerm("definition"), ast.NewTerm(definition)),
		ast.Item(ast.StringTerm("meta"), ast.NewTerm(meta)),
		ast.Item(ast.StringTerm("value"), astValue),
	)
	return astProp, nil
}
