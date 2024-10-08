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

package functions_test

import (
	"context"
	"fmt"
	"time"

	"github.com/indykite/indykite-sdk-go/authorization"
	authorizationpb "github.com/indykite/indykite-sdk-go/gen/indykite/authorization/v1beta1"
	"github.com/indykite/indykite-sdk-go/test"
	authorizationm "github.com/indykite/indykite-sdk-go/test/authorization/v1beta1"
	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/indykite/opa-indykite-plugin/functions"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("indy.who_authorized", func() {
	var (
		mockCtrl                *gomock.Controller
		mockAuthorizationClient *authorizationm.MockAuthorizationAPIClient
		oldConnection           *authorization.Client
		idFn                    = func(subject interface{}) string {
			switch r := subject.(type) {
			case map[string]interface{}:
				return fmt.Sprintf("%v", r["externalId"])
			default:
				return "somethingthatshouldnowork"
			}
		}
	)
	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockAuthorizationClient = authorizationm.NewMockAuthorizationAPIClient(mockCtrl)
		client, _ := authorization.NewClientFromGRPCClient(mockAuthorizationClient)
		oldConnection = functions.OverrideAuthorizationClient(client)
	})
	AfterEach(func() {
		functions.OverrideAuthorizationClient(oldConnection)
	})
	It("happy path", func() {
		mockAuthorizationClient.EXPECT().WhoAuthorized(
			gomock.Any(),
			WrapMatcher(EqualProto(&authorizationpb.WhoAuthorizedRequest{
				Resources: []*authorizationpb.WhoAuthorizedRequest_Resource{
					{ExternalId: "res1", Type: "Type", Actions: []string{"READ"}},
					{ExternalId: "res2", Type: "Type", Actions: []string{"READ"}},
				},
				InputParams: map[string]*authorizationpb.InputParam{
					"string":  {Value: &authorizationpb.InputParam_StringValue{StringValue: "42"}},
					"boolean": {Value: &authorizationpb.InputParam_BoolValue{BoolValue: true}},
					"double":  {Value: &authorizationpb.InputParam_DoubleValue{DoubleValue: 4.2}},
					"integer": {Value: &authorizationpb.InputParam_IntegerValue{IntegerValue: 42}},
				},
				PolicyTags: []string{"42"},
			})),
		).Return(&authorizationpb.WhoAuthorizedResponse{
			DecisionTime: timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
			Decisions: map[string]*authorizationpb.WhoAuthorizedResponse_ResourceType{
				"Type": {
					Resources: map[string]*authorizationpb.WhoAuthorizedResponse_Resource{
						"res1": {
							Actions: map[string]*authorizationpb.WhoAuthorizedResponse_Action{
								"READ": {Subjects: []*authorizationpb.WhoAuthorizedResponse_Subject{
									{ExternalId: "subA"},
								}},
							},
						},
						"res2": {
							Actions: map[string]*authorizationpb.WhoAuthorizedResponse_Action{
								"READ": {Subjects: []*authorizationpb.WhoAuthorizedResponse_Subject{
									{ExternalId: "subB"},
								}},
							},
						},
					},
				},
			},
		}, nil)

		r := rego.New(rego.Query(
			`x = indy.who_authorized([{"externalId": "res1", "type": "Type", "actions": ["READ"]},{"externalId": "res2", "type": "Type", "actions": ["READ"]}], {"string": {"string_value":"42"}, "integer": {"integer_value":42}, "double": {"double_value":4.2}, "boolean": {"bool_value":true}}, ["42"])`)) //nolint:lll

		ctx := context.Background()
		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(err).To(Succeed())
		Expect(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
			"error":        BeNil(),
			"decisionTime": BeEquivalentTo("1645543102"), // All numbers are json.Number ie string,
			"decisions": MatchAllKeys(Keys{
				"Type": MatchAllKeys(Keys{
					"res1": MatchAllKeys(Keys{
						"READ": MatchAllElements(idFn, Elements{
							"subA": MatchAllKeys(Keys{
								"externalId": Equal("subA"),
							}),
						}),
					}),
					"res2": MatchAllKeys(Keys{
						"READ": MatchAllElements(idFn, Elements{
							"subB": MatchAllKeys(Keys{
								"externalId": Equal("subB"),
							}),
						}),
					}),
				}),
			}),
		}))
	})
	DescribeTable("Invalid input arguments - gRPC error",
		func(regoParams string, errorMessage string, originMessage string) {
			q := `x = indy.who_authorized(` + regoParams + `)`
			ctx := context.Background()

			r := rego.New(rego.Query(q))

			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(err).To(Succeed())
			errKeys := Keys{
				"grpc_errno": BeEquivalentTo("3"), // All numbers are json.Number ie string
				"grpc_error": Equal("InvalidArgument"),
				"message":    ContainSubstring(errorMessage),
			}
			if originMessage != "" {
				errKeys["origin"] = ContainSubstring(originMessage)
			}
			Expect(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
				"error": MatchAllKeys(errKeys),
			}))
		},
		Entry("Empty resources", `[], {}, []`,
			"unable to call WhoAuthorized client endpoint", "Resources: value must contain between 1 and 32 items"),
	)
	It("Service backend error", func() {
		ctx := context.Background()
		mockAuthorizationClient.EXPECT().
			WhoAuthorized(gomock.Any(), gomock.Any()).
			Times(2).
			Return(nil, status.Error(codes.Internal, "oops"))

		// With StrictBuiltinErrors
		r := rego.New(
			rego.Query(`x = indy.who_authorized([{"externalId": "res1", "type": "Type", "actions": ["READ"]}], {}, [])`), //nolint:lll
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.who_authorized: client error: code = Internal desc = oops")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.who_authorized([{"externalId": "res1", "type": "Type", "actions": ["READ"]}], {}, [])`)) //nolint:lll

		query, err = r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err = query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(Succeed())
	})
	It("Fail to create client", func() {
		ctx := context.Background()

		functions.OverrideAuthorizationClient(nil)

		// With StrictBuiltinErrors
		r := rego.New(
			rego.Query(`x = indy.who_authorized([{"externalId": "res1", "type": "Type", "actions": ["READ"]}], {}, [])`), //nolint:lll
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.who_authorized: missing endpoint")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.who_authorized([{"externalId": "res1", "type": "Type", "actions": ["READ"]}], {}, [])`)) //nolint:lll

		query, err = r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err = query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(Succeed())
	})
	DescribeTable("Testing options",
		func(regoOptions string, inputParams map[string]*authorizationpb.InputParam, policyTags []string) {
			request := &authorizationpb.WhoAuthorizedRequest{
				Resources: []*authorizationpb.WhoAuthorizedRequest_Resource{
					{ExternalId: "res1", Type: "Type", Actions: []string{"READ"}},
				},
				InputParams: inputParams,
				PolicyTags:  policyTags,
			}

			mockAuthorizationClient.EXPECT().WhoAuthorized(
				gomock.Any(),
				WrapMatcher(test.EqualProto(request)),
			).Return(&authorizationpb.WhoAuthorizedResponse{
				DecisionTime: timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
				Decisions: map[string]*authorizationpb.WhoAuthorizedResponse_ResourceType{
					"Type": {
						Resources: map[string]*authorizationpb.WhoAuthorizedResponse_Resource{
							"res1": {
								Actions: map[string]*authorizationpb.WhoAuthorizedResponse_Action{
									"READ": {Subjects: []*authorizationpb.WhoAuthorizedResponse_Subject{
										{ExternalId: "subA"},
									}},
								},
							},
						},
					},
				},
			}, nil)

			q := `x = indy.who_authorized([{"externalId": "res1", "type": "Type", "actions": ["READ"]}],` + regoOptions + `)` //nolint:lll
			r := rego.New(rego.Query(q))

			ctx := context.Background()
			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(err).To(Succeed())
			Expect(rs[0].Bindings["x"]).To(Not(BeNil()))
		},
		Entry("Empty options", `{},[]`, nil, nil),
		Entry("inputParams - String param", `{ "string": {"string_value":"42" }},[]`,
			map[string]*authorizationpb.InputParam{
				"string": {Value: &authorizationpb.InputParam_StringValue{StringValue: "42"}},
			},
			nil,
		),
		Entry("inputParams - Bool and integer param",
			`{ "boolean": {"bool_value":true}, "integer": {"integer_value":42} }, []`,
			map[string]*authorizationpb.InputParam{
				"boolean": {Value: &authorizationpb.InputParam_BoolValue{BoolValue: true}},
				"integer": {Value: &authorizationpb.InputParam_IntegerValue{IntegerValue: 42}},
			},
			nil,
		),
		Entry("policyTags - empty array", ` {}, []`, nil, nil),
		Entry("policyTags - two values in array", ` {}, ["42", "24"]`, nil, []string{"42", "24"}),
	)
})
