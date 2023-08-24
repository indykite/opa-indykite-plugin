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
	"fmt"

	"github.com/indykite/indykite-sdk-go/errors"
	identity "github.com/indykite/indykite-sdk-go/gen/indykite/identity/v1beta2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/indykite/opa-indykite-plugin/utilities"
)

func init() {
	rego.RegisterBuiltin1(
		&rego.Function{
			Name:    "indy.identity",
			Decl:    types.NewFunction(types.Args(types.S), types.A),
			Memoize: true,
		},
		func(bCtx rego.BuiltinContext, tokenTerm *ast.Term) (*ast.Term, error) {
			var token string

			if err := ast.As(tokenTerm.Value, &token); err != nil {
				return nil, err
			}

			client, err := IdentityClient(bCtx.Context)
			if err != nil {
				return nil, err
			}
			resp, err := client.IntrospectToken(bCtx.Context, token)
			obj := ast.NewObject()

			if statusErr := errors.FromError(err); statusErr != nil {
				if errors.IsServiceError(statusErr) {
					return nil, statusErr
				}
				obj.Insert(ast.StringTerm("error"), utilities.BuildUserError(statusErr))
			} else {
				obj.Insert(ast.StringTerm("error"), ast.NullTerm())
				obj.Insert(ast.StringTerm("active"), ast.BooleanTerm(resp.Active))
				if ti := resp.GetTokenInfo(); ti != nil {
					if err = fillAstWithTokenInfo(obj, ti); err != nil {
						return nil, err
					}
				}
			}

			return &ast.Term{Value: obj}, nil
		},
	)
}

func fillAstWithTokenInfo(obj ast.Object, resp *identity.IdentityTokenInfo) error {
	exp, _ := ast.InterfaceToValue(resp.GetExpireTime().AsTime().Unix())
	obj.Insert(ast.StringTerm("expire"), ast.NewTerm(exp))
	obj.Insert(ast.StringTerm("customerId"), ast.StringTerm(resp.CustomerId))
	obj.Insert(ast.StringTerm("appSpaceId"), ast.StringTerm(resp.AppSpaceId))
	obj.Insert(ast.StringTerm("applicationId"), ast.StringTerm(resp.ApplicationId))
	obj.Insert(ast.StringTerm("subjectId"), ast.StringTerm(resp.GetSubject().GetId()))
	obj.Insert(ast.StringTerm("tenantId"), ast.StringTerm(resp.GetSubject().GetTenantId()))

	if resp.GetImpersonated() != nil {
		obj.Insert(ast.StringTerm("impersonatedId"), ast.StringTerm(resp.Impersonated.Id))
	} else {
		obj.Insert(ast.StringTerm("impersonatedId"), ast.StringTerm(""))
	}

	terms, err := parseCustomClaims(resp.GetTokenClaims())
	if err != nil {
		return err
	}
	obj.Insert(ast.StringTerm("tokenClaims"), ast.ObjectTerm(terms...))

	terms, err = parseCustomClaims(resp.GetSessionClaims())
	if err != nil {
		return err
	}
	obj.Insert(ast.StringTerm("sessionClaims"), ast.ObjectTerm(terms...))

	return nil
}

func parseCustomClaims(claims *structpb.Struct) ([][2]*ast.Term, error) {
	var claimTerms [][2]*ast.Term
	if claims != nil {
		for key, value := range claims.AsMap() {
			v, err := ast.InterfaceToValue(value)
			if err != nil {
				return nil, fmt.Errorf("cannot parse map key '%s': %v", key, err)
			}
			claimTerm := [2]*ast.Term{ast.StringTerm(key), ast.NewTerm(v)}
			claimTerms = append(claimTerms, claimTerm)
		}
	}
	return claimTerms, nil
}
