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

package utilities

import (
	"encoding/base64"
	"fmt"
	"time"

	sdkerrors "github.com/indykite/indykite-sdk-go/errors"
	objects "github.com/indykite/indykite-sdk-go/gen/indykite/objects/v1beta1"
	"github.com/open-policy-agent/opa/ast"
)

// BuildUserError converts StatusError into *ast.Term to return to user.
// Should not be called when sdkerrors.IsServiceError(err) returns true.
func BuildUserError(err *sdkerrors.StatusError) *ast.Term {
	astErr := ast.NewObject(
		ast.Item(ast.StringTerm("message"), ast.StringTerm(err.Message())),
		ast.Item(ast.StringTerm("grpc_errno"), ast.IntNumberTerm(int(err.Code()))),
		ast.Item(ast.StringTerm("grpc_error"), ast.StringTerm(err.Code().String())),
	)
	if origin := err.Origin(); origin != nil {
		astErr.Insert(ast.StringTerm("origin"), ast.StringTerm(origin.Error()))
	}
	return ast.NewTerm(astErr)
}

// ObjectsValueIntoAstTerm converts recursively *objects.Value into *ast.Term
// Duration, Identifier and Any is not supported
// Time is converted to string in RFC3339 format
// Bytes are converted to string as Base64 Standart encoded string
// nolint:cyclop
func ObjectsValueIntoAstTerm(objVal *objects.Value) (*ast.Term, error) {
	if objVal.GetValue() == nil {
		return ast.NullTerm(), nil
	}

	switch pv := objVal.Value.(type) {
	case *objects.Value_NullValue:
		return ast.NullTerm(), nil
	case *objects.Value_BoolValue:
		return ast.BooleanTerm(pv.BoolValue), nil
	case *objects.Value_IntegerValue:
		return ast.IntNumberTerm(int(pv.IntegerValue)), nil
	case *objects.Value_UnsignedIntegerValue:
		return ast.UIntNumberTerm(pv.UnsignedIntegerValue), nil
	case *objects.Value_DoubleValue:
		return ast.FloatNumberTerm(pv.DoubleValue), nil
	case *objects.Value_ValueTime:
		if pv.ValueTime == nil {
			return ast.NullTerm(), nil
		}
		return ast.StringTerm(pv.ValueTime.AsTime().Format(time.RFC3339)), nil
	case *objects.Value_StringValue:
		return ast.StringTerm(pv.StringValue), nil
	case *objects.Value_BytesValue:
		// Stay with Standart encoding for know, Rego has built-in functions for both types of Base64
		// https://www.openpolicyagent.org/docs/latest/policy-reference/#encoding
		return ast.StringTerm(base64.StdEncoding.EncodeToString(pv.BytesValue)), nil
	case *objects.Value_GeoPointValue:
		return ast.StringTerm(
			fmt.Sprintf("POINT (%v %v)", pv.GeoPointValue.GetLatitude(), pv.GeoPointValue.GetLongitude())), nil
	case *objects.Value_ArrayValue:
		if pv.ArrayValue == nil {
			return ast.NullTerm(), nil
		}
		values := pv.ArrayValue.Values
		ret := ast.NewArray()
		for _, v := range values {
			r, err := ObjectsValueIntoAstTerm(v)
			if err != nil {
				return nil, err
			}
			ret = ret.Append(r)
		}
		return ast.NewTerm(ret), nil
	case *objects.Value_MapValue:
		if pv.MapValue == nil {
			return ast.NullTerm(), nil
		}
		ret := ast.NewObject()
		for k, v := range pv.MapValue.Fields {
			r, err := ObjectsValueIntoAstTerm(v)
			if err != nil {
				return nil, err
			}
			ret.Insert(ast.StringTerm(k), r)
		}
		return ast.NewTerm(ret), nil
	default:
		return nil, fmt.Errorf("value of type '%T' cannot be converted to *ast.Term", objVal.Value)
	}
}
