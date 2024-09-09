// Copyright (c) 2024 IndyKite
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
	"fmt"
	"time"

	authorizationv1beta1 "github.com/indykite/indykite-sdk-go/gen/indykite/authorization/v1beta1"
	objectsv1beta2 "github.com/indykite/indykite-sdk-go/gen/indykite/objects/v1beta2"
	"github.com/onsi/gomega/types"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/indykite/opa-indykite-plugin/utilities"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func newError(key, value *ast.Term) error {
	valueError := fmt.Errorf("invalid value: %v", value)
	return builtins.NewOperandErr(3, "invalid input parameter %s: %v", key, valueError)
}

var _ = Describe("ParseInputParams", func() {
	DescribeTable("Errors",
		func(term *ast.Term, errorMatcher types.GomegaMatcher) {
			res, err := utilities.ParseInputParams(term, 3)
			Expect(res).To(BeNil())
			Expect(err).To(errorMatcher)
		},
		Entry("nil term",
			nil,
			BeNil(),
		),
		Entry("not an object",
			ast.StringTerm("sth"),
			BeNil(),
		),
		Entry("not an string",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("string_value"),
					ast.BooleanTerm(false),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("string_value"),
					ast.BooleanTerm(false),
				}),
			)),
		),
		Entry("not a bool",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("bool_value"),
					ast.NumberTerm("66"),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("bool_value"),
					ast.NumberTerm("66"),
				}),
			)),
		),
		Entry("not an integer",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("integer_value"),
					ast.BooleanTerm(false),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("integer_value"),
					ast.BooleanTerm(false),
				}),
			)),
		),
		Entry("not a double",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("double_value"),
					ast.BooleanTerm(false),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("double_value"),
					ast.BooleanTerm(false),
				}),
			)),
		),
		Entry("not a time",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("time_value"),
					ast.BooleanTerm(false),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("time_value"),
					ast.BooleanTerm(false),
				}),
			)),
		),
		Entry("not a duration",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("duration_value"),
					ast.BooleanTerm(false),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("duration_value"),
					ast.BooleanTerm(false),
				}),
			)),
		),
		Entry("not an array",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("array_value"),
					ast.BooleanTerm(false),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("array_value"),
					ast.BooleanTerm(false),
				}),
			)),
		),
		Entry("array missing values",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("array_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("fields"),
						ast.BooleanTerm(false),
					}),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("array_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("fields"),
						ast.BooleanTerm(false),
					}),
				}),
			)),
		),
		Entry("values are not array",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("array_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("values"),
						ast.BooleanTerm(false),
					}),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("array_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("values"),
						ast.BooleanTerm(false),
					}),
				}),
			)),
		),
		Entry("not a map",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("map_value"),
					ast.BooleanTerm(false),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("map_value"),
					ast.BooleanTerm(false),
				}),
			)),
		),
		Entry("map missing fields",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("map_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("values"),
						ast.BooleanTerm(false),
					}),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("map_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("values"),
						ast.BooleanTerm(false),
					}),
				}),
			)),
		),
		Entry("fields is not an object",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("map_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("fields"),
						ast.BooleanTerm(false),
					}),
				}),
			}),
			Equal(newError(
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("map_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("fields"),
						ast.BooleanTerm(false),
					}),
				}),
			)),
		),
	)
	DescribeTable("Succeeds",
		func(term *ast.Term, result map[string]*authorizationv1beta1.InputParam) {
			res, err := utilities.ParseInputParams(term, 3)
			Expect(err).To(Succeed())
			Expect(res).To(Equal(result))
		},
		Entry("String value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("string_value"),
					ast.StringTerm("value X"),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_StringValue{StringValue: "value X"},
				},
			},
		),
		Entry("Bool value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("bool_value"),
					ast.BooleanTerm(true),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_BoolValue{BoolValue: true},
				},
			},
		),
		Entry("Integer value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("integer_value"),
					ast.NumberTerm("66"),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_IntegerValue{IntegerValue: 66},
				},
			},
		),
		Entry("Double value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("double_value"),
					ast.NumberTerm("66.66"),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_DoubleValue{DoubleValue: 66.66},
				},
			},
		),
		Entry("Time value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("time_value"),
					ast.StringTerm("2020-03-03T16:24:59-0300"),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_TimeValue{TimeValue: timestamppb.New(
						time.Date(2020, 3, 3, 16, 24, 59, 0, time.FixedZone("UTC-3", -3*60*60)),
					)},
				},
			},
		),
		Entry("Duration value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("duration_value"),
					ast.StringTerm("66.003s"),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_DurationValue{
						DurationValue: durationpb.New(time.Second*66 + time.Millisecond*3),
					},
				},
			},
		),
		Entry("Array value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("array_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("values"),
						ast.ArrayTerm(
							ast.ObjectTerm([2]*ast.Term{
								ast.StringTerm("integer_value"),
								ast.NumberTerm("66"),
							}),
							ast.ObjectTerm([2]*ast.Term{
								ast.StringTerm("bool_value"),
								ast.BooleanTerm(true),
							}),
						),
					}),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_ArrayValue{
						ArrayValue: &objectsv1beta2.Array{
							Values: []*objectsv1beta2.Value{{
								Type: &objectsv1beta2.Value_IntegerValue{IntegerValue: 66},
							}, {
								Type: &objectsv1beta2.Value_BoolValue{BoolValue: true},
							}},
						},
					},
				},
			},
		),
		Entry("Map value",
			ast.ObjectTerm([2]*ast.Term{
				ast.StringTerm("paramX"),
				ast.ObjectTerm([2]*ast.Term{
					ast.StringTerm("map_value"),
					ast.ObjectTerm([2]*ast.Term{
						ast.StringTerm("fields"),
						ast.ObjectTerm(
							[2]*ast.Term{
								ast.StringTerm("field1"),
								ast.ObjectTerm([2]*ast.Term{
									ast.StringTerm("integer_value"),
									ast.NumberTerm("66"),
								}),
							},
							[2]*ast.Term{
								ast.StringTerm("field2"),
								ast.ObjectTerm([2]*ast.Term{
									ast.StringTerm("bool_value"),
									ast.BooleanTerm(true),
								}),
							},
						),
					}),
				}),
			}),
			map[string]*authorizationv1beta1.InputParam{
				"paramX": {
					Value: &authorizationv1beta1.InputParam_MapValue{
						MapValue: &objectsv1beta2.Map{
							Fields: map[string]*objectsv1beta2.Value{
								"field1": {
									Type: &objectsv1beta2.Value_IntegerValue{IntegerValue: 66},
								},
								"field2": {
									Type: &objectsv1beta2.Value_BoolValue{BoolValue: true},
								},
							},
						},
					},
				},
			},
		),
	)
})
