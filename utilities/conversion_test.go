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

package utilities_test

import (
	"time"

	objects "github.com/indykite/indykite-sdk-go/gen/indykite/objects/v1beta1"
	"github.com/onsi/gomega/types"
	"github.com/open-policy-agent/opa/ast"
	latlng "google.golang.org/genproto/googleapis/type/latlng"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/indykite/opa-indykite-plugin/utilities"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Conversion", func() {
	DescribeTable("objectsValueIntoAstTerm",
		func(objVal *objects.Value, errMatcher, valueMatcher types.GomegaMatcher) {
			astTerm, err := utilities.ObjectsValueIntoAstTerm(objVal)
			Expect(err).To(errMatcher)
			if err == nil {
				Expect(astTerm.Value).To(valueMatcher)
			}
		},
		Entry("Nil param", nil, Succeed(), BeAssignableToTypeOf(ast.Null{})),
		Entry("Empty param", &objects.Value{}, Succeed(), BeAssignableToTypeOf(ast.Null{})),
		Entry("Null value", objects.Null(), Succeed(), BeAssignableToTypeOf(ast.Null{})),
		Entry("Bool value", objects.Bool(true), Succeed(), BeEquivalentTo(true)),
		Entry("Int value", objects.Int64(-44357), Succeed(), BeEquivalentTo("-44357")),
		Entry("Unsigned int value", &objects.Value{
			Value: &objects.Value_UnsignedIntegerValue{UnsignedIntegerValue: 43574},
		}, Succeed(), BeEquivalentTo("43574")),
		Entry("Float value", objects.Float64(12.773), Succeed(), BeEquivalentTo("12.773")),
		Entry("Null time value",
			&objects.Value{Value: &objects.Value_ValueTime{}}, Succeed(), BeAssignableToTypeOf(ast.Null{})),
		Entry("Time value",
			&objects.Value{Value: &objects.Value_ValueTime{
				ValueTime: timestamppb.New(time.Date(2020, 8, 8, 8, 8, 8, 0, time.UTC))}},
			Succeed(),
			BeEquivalentTo("2020-08-08T08:08:08Z"),
		),
		Entry("String value", objects.String("opa-test-str"), Succeed(), BeEquivalentTo("opa-test-str")),
		Entry("Bytes value",
			&objects.Value{Value: &objects.Value_BytesValue{BytesValue: []byte("bytes-from-~string-123")}},
			Succeed(),
			BeEquivalentTo("Ynl0ZXMtZnJvbS1+c3RyaW5nLTEyMw=="),
		),
		Entry("Geo point", &objects.Value{Value: &objects.Value_GeoPointValue{GeoPointValue: &latlng.LatLng{
			Latitude:  20.77,
			Longitude: 14.58,
		}}}, Succeed(), BeEquivalentTo("POINT (20.77 14.58)")),
		Entry("Any value", &objects.Value{Value: &objects.Value_AnyValue{}}, MatchError(
			MatchRegexp("value of type '.*' cannot be converted to .ast.Term"),
		), BeNil()),
	)
	It("objectsValueIntoAstTerm with array", func() {
		astTerm, err := utilities.ObjectsValueIntoAstTerm(&objects.Value{Value: &objects.Value_ArrayValue{
			ArrayValue: &objects.ArrayValue{
				Values: []*objects.Value{objects.Bool(true), objects.String("abc"), objects.Int64(147)},
			},
		}})
		Expect(err).To(Succeed())
		astArr, ok := astTerm.Value.(*ast.Array)
		Expect(ok).To(BeTrue())
		Expect(astArr.Len()).To(Equal(3))
		Expect(astArr.Elem(0).Value).To(BeEquivalentTo(true))
		Expect(astArr.Elem(1).Value).To(BeEquivalentTo("abc"))
		Expect(astArr.Elem(2).Value).To(BeEquivalentTo("147"))
	})

	It("objectsValueIntoAstTerm with map", func() {
		astTerm, err := utilities.ObjectsValueIntoAstTerm(&objects.Value{Value: &objects.Value_MapValue{
			MapValue: &objects.MapValue{Fields: map[string]*objects.Value{
				"bool_key":  objects.Bool(true),
				"str_key":   objects.String("olala"),
				"float_key": objects.Float64(78.96),
			}},
		}})
		Expect(err).To(Succeed())
		astArr, ok := astTerm.Value.(ast.Object)
		Expect(ok).To(BeTrue())
		Expect(astArr.Len()).To(Equal(3))
		Expect(astArr.Get(ast.StringTerm("bool_key")).Value).To(BeEquivalentTo(true))
		Expect(astArr.Get(ast.StringTerm("str_key")).Value).To(BeEquivalentTo("olala"))
		Expect(astArr.Get(ast.StringTerm("float_key")).Value).To(BeEquivalentTo("78.96"))
	})
})
