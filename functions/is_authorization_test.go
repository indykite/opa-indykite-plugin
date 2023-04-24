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

package functions_test

import (
	"context"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/indykite/jarvis-sdk-go/authorization"
	authorizationpb "github.com/indykite/jarvis-sdk-go/gen/indykite/authorization/v1beta1"
	identitypb "github.com/indykite/jarvis-sdk-go/gen/indykite/identity/v1beta2"
	objects "github.com/indykite/jarvis-sdk-go/gen/indykite/objects/v1beta1"
	"github.com/indykite/jarvis-sdk-go/test"
	authorizationm "github.com/indykite/jarvis-sdk-go/test/authorization/v1beta1"
	"github.com/open-policy-agent/opa/rego"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/indykite/opa-indykite-plugin/functions"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("indy.is_authorized", func() {
	var (
		mockCtrl                *gomock.Controller
		mockAuthorizationClient *authorizationm.MockAuthorizationAPIClient
		oldConnection           *authorization.Client
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

	type dtIDCase struct {
		reqSubject          *authorizationpb.Subject
		respDecisionTime    *timestamppb.Timestamp
		respTTL             *durationpb.Duration
		regoParam1          string
		decisionTimeMatcher OmegaMatcher
		ttlMatcher          OmegaMatcher
	}
	DescribeTable("Call with DT Identifier as",
		func(c *dtIDCase) {
			mockAuthorizationClient.EXPECT().IsAuthorized(
				gomock.Any(),
				WrapMatcher(EqualProto(&authorizationpb.IsAuthorizedRequest{
					Subject: c.reqSubject,
					Resources: []*authorizationpb.IsAuthorizedRequest_Resource{
						{Id: "res1", Type: "Type", Actions: []string{"READ"}},
						{Id: "res2", Type: "Type", Actions: []string{"READ"}},
					},
					InputParams: map[string]*authorizationpb.InputParam{
						"string":  {Value: &authorizationpb.InputParam_StringValue{StringValue: "42"}},
						"boolean": {Value: &authorizationpb.InputParam_BoolValue{BoolValue: true}},
						"double":  {Value: &authorizationpb.InputParam_DoubleValue{DoubleValue: 4.2}},
						"integer": {Value: &authorizationpb.InputParam_IntegerValue{IntegerValue: 42}},
					},
					PolicyTags: []string{"42"},
				})),
			).Return(&authorizationpb.IsAuthorizedResponse{
				DecisionTime: c.respDecisionTime,
				Decisions: map[string]*authorizationpb.IsAuthorizedResponse_ResourceType{
					"Type": {
						Resources: map[string]*authorizationpb.IsAuthorizedResponse_Resource{
							"res1": {
								Actions: map[string]*authorizationpb.IsAuthorizedResponse_Action{
									"READ": {Allow: true},
								},
							},
							"res2": {
								Actions: map[string]*authorizationpb.IsAuthorizedResponse_Action{
									"READ": {Allow: true},
								},
							},
						},
					},
				},
			}, nil)

			r := rego.New(rego.Query(
				`x = indy.is_authorized(` + c.regoParam1 + `,[{"id": "res1", "type": "Type", "actions": ["READ"]},{"id": "res2", "type": "Type", "actions": ["READ"]}], {"input_params": {"string": "42", "integer": 42, "double": 4.2, "boolean": true}, "policy_tags": ["42"]})`)) //nolint:lll

			ctx := context.Background()
			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(err).To(Succeed())
			Expect(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
				"error":         BeNil(),
				"decision_time": c.decisionTimeMatcher,
				"decisions": MatchAllKeys(Keys{
					"Type": MatchAllKeys(Keys{
						"res1": MatchAllKeys(Keys{
							"READ": MatchAllKeys(Keys{
								"allow": Equal(true),
							}),
						}),
						"res2": MatchAllKeys(Keys{
							"READ": MatchAllKeys(Keys{
								"allow": Equal(true),
							}),
						}),
					}),
				}),
			}))
		},
		Entry("Access Token", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_DigitalTwinIdentifier{
					DigitalTwinIdentifier: &identitypb.DigitalTwinIdentifier{
						Filter: &identitypb.DigitalTwinIdentifier_AccessToken{AccessToken: testAccessToken},
					},
				},
			},
			respDecisionTime:    timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
			respTTL:             durationpb.New(time.Minute * 90),
			decisionTimeMatcher: BeEquivalentTo("1645543102"), // All numbers are json.Number ie string
			ttlMatcher:          BeEquivalentTo("5400"),
			regoParam1:          `"` + testAccessToken + `"`,
		}),
		Entry("DigitalTwin", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_DigitalTwinIdentifier{
					DigitalTwinIdentifier: &identitypb.DigitalTwinIdentifier{
						Filter: &identitypb.DigitalTwinIdentifier_DigitalTwin{
							DigitalTwin: &identitypb.DigitalTwin{
								Id:       "gid:AAAAFezuHiJHiUeRjrIJV8k3oKo",
								TenantId: "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35f",
							},
						},
					},
				},
			},
			// Test also nil values
			respDecisionTime:    nil,
			respTTL:             nil,
			decisionTimeMatcher: BeEquivalentTo("0"),
			ttlMatcher:          BeEquivalentTo("0"),
			regoParam1:          `{"digital_twin_id": "gid:AAAAFezuHiJHiUeRjrIJV8k3oKo", "tenant_id": "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35f"}`, // nolint:lll
		}),
		Entry("DigitalTwin property", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_DigitalTwinIdentifier{
					DigitalTwinIdentifier: &identitypb.DigitalTwinIdentifier{
						Filter: &identitypb.DigitalTwinIdentifier_PropertyFilter{
							PropertyFilter: &identitypb.PropertyFilter{
								Type:  "email",
								Value: objects.String("sam@sung.com"),
							},
						},
					},
				},
			},
			// Test also nil values
			respDecisionTime:    nil,
			respTTL:             nil,
			decisionTimeMatcher: BeEquivalentTo("0"),
			ttlMatcher:          BeEquivalentTo("0"),
			regoParam1:          `{"property_type": "email", "property_value": "sam@sung.com"}`,
		}),
	)

	//nolint:lll
	DescribeTable("Invalid input arguments - gRPC error",
		func(regoParams string, errorMessage string, originMessage string) {
			q := `x = indy.is_authorized(` + regoParams + `)`
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
		Entry("Request validation fail", `"a", [{"id": "res1", "type": "Type", "actions": ["READ"]}, {"id": "res2", "type": "Type", "actions": ["READ"]}], {}`,
			"unable to call IsAuthorized client endpoint", "AccessToken: value length must be at least 20 runes"),
		Entry("Invalid access token", `"aaaaaaaaaaaaaaaaaaaa", [{"id": "res1", "type": "Type", "actions": ["READ"]}, {"id": "res2", "type": "Type", "actions": ["READ"]}], {}`,
			"invalid token format", "failed to parse token: invalid character 'a' looking for beginning of value"),
		Entry("Empty actions", `"`+testAccessToken+`", [{"id": "res1", "type": "Type", "actions": []}, {"id": "res2", "type": "Type", "actions": []}], {}`,
			"unable to call IsAuthorized client endpoint",
			"Actions: value must contain between 1 and 5 items"),
		Entry("Empty resource_references", `"`+testAccessToken+`", [], {}`,
			"unable to call IsAuthorized client endpoint",
			"invalid IsAuthorizedRequest.Resources: value must contain between 1 and 32 items, inclusive"),
		Entry("Invalid digital twin", `{"digital_twin_id": "22", "tenant_id": ""}, [{"id": "res1", "type": "Type", "actions": ["READ"]}, {"id": "res2", "type": "Type", "actions": ["READ"]}], {}`,
			"unable to call IsAuthorized client endpoint",
			"invalid DigitalTwin.Id: value length must be between 27 and 100 runes"),
		Entry("Invalid tenant_id", `{"digital_twin_id": "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35a", "tenant_id": ""}, [{"id": "res1", "type": "Type", "actions": ["READ"]}, {"id": "res2", "type": "Type", "actions": ["READ"]}], {}`,
			"unable to call IsAuthorized client endpoint",
			"invalid DigitalTwin.TenantId: value length must be between 27 and 100 runes"),
		//	TODO: include these once proto file has validation on PropertyFilter
		XEntry("Invalid property_type", `{"property_type": "", "property_value": ""}, [{"id": "res1", "type": "Type", "actions": ["READ"]}, {"id": "res2", "type": "Type", "actions": ["READ"]}], {}`,
			"unable to call IsAuthorized client endpoint",
			"some error here"),
		XEntry("Invalid property_value", `{"property_type": "email", "property_value": ""}, [{"id": "res1", "type": "Type", "actions": ["READ"]}, {"id": "res2", "type": "Type", "actions": ["READ"]}], {}`,
			"unable to call IsAuthorized client endpoint",
			"some error here"),
	)

	It("Service backend error", func() {
		ctx := context.Background()
		mockAuthorizationClient.EXPECT().
			IsAuthorized(gomock.Any(), gomock.Any()).
			Times(2).
			Return(nil, status.Error(codes.Internal, "oops"))

		// With StrictBuiltinErrors
		r := rego.New(
			rego.Query(`x = indy.is_authorized("`+testAccessToken+`", [{"id": "res1", "type": "Type", "actions": ["READ"]}], {})`), //nolint:lll
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.is_authorized: client error: code = Internal desc = oops")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.is_authorized("` + testAccessToken + `", [{"id": "res1", "type": "Type", "actions": ["READ"]}], {})`)) //nolint:lll

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
			rego.Query(`x = indy.is_authorized("`+testAccessToken+`", [{"id": "res1", "type": "Type", "actions": ["READ"]}], {})`), //nolint:lll
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.is_authorized: missing endpoint")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.is_authorized("` + testAccessToken + `", [{"id": "res1", "type": "Type", "actions": ["READ"]}], {})`)) //nolint:lll

		query, err = r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err = query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(Succeed())
	})
	DescribeTable("Testing options",
		func(regoOptions string, inputParams map[string]*authorizationpb.InputParam, policyTags []string) {
			request := &authorizationpb.IsAuthorizedRequest{
				Subject: &authorizationpb.Subject{
					Subject: &authorizationpb.Subject_DigitalTwinIdentifier{
						DigitalTwinIdentifier: &identitypb.DigitalTwinIdentifier{
							Filter: &identitypb.DigitalTwinIdentifier_AccessToken{AccessToken: testAccessToken},
						},
					},
				},
				Resources: []*authorizationpb.IsAuthorizedRequest_Resource{
					{Id: "res1", Type: "Type", Actions: []string{"READ"}},
				},
				InputParams: inputParams,
				PolicyTags:  policyTags,
			}

			mockAuthorizationClient.EXPECT().IsAuthorized(
				gomock.Any(),
				WrapMatcher(test.EqualProto(request)),
			).Return(&authorizationpb.IsAuthorizedResponse{
				DecisionTime: timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
				Decisions: map[string]*authorizationpb.IsAuthorizedResponse_ResourceType{
					"Type": {
						Resources: map[string]*authorizationpb.IsAuthorizedResponse_Resource{
							"res1": {
								Actions: map[string]*authorizationpb.IsAuthorizedResponse_Action{
									"READ": {Allow: true},
								},
							},
						},
					},
				},
			}, nil)

			q := `x = indy.is_authorized("` + testAccessToken + `",[{"id": "res1", "type": "Type", "actions": ["READ"]}],` + regoOptions + `)` //nolint:lll
			r := rego.New(rego.Query(q))

			ctx := context.Background()
			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(err).To(Succeed())
			Expect(rs[0].Bindings["x"]).To(Not(BeNil()))
		},
		Entry("Empty options", `{}`, nil, nil),
		Entry("input_params - String param", `{"input_params": { "string": "42" }}`,
			map[string]*authorizationpb.InputParam{
				"string": {Value: &authorizationpb.InputParam_StringValue{StringValue: "42"}},
			},
			nil,
		),
		Entry("input_params - Bool and integer param", `{"input_params": { "boolean": true, "integer": 42 }}`,
			map[string]*authorizationpb.InputParam{
				"boolean": {Value: &authorizationpb.InputParam_BoolValue{BoolValue: true}},
				"integer": {Value: &authorizationpb.InputParam_IntegerValue{IntegerValue: 42}},
			},
			nil,
		),
		Entry("policy_tags - wrong object type", `{"policy_tags": "invalid"}`, nil, nil),
		Entry("policy_tags - empty array", `{"policy_tags": []}`, nil, nil),
		Entry("policy_tags - wrong value in array", `{"policy_tags": [42]}`, nil, nil),
		Entry("policy_tags - two values in array", `{"policy_tags": ["42", "24"]}`, nil, []string{"42", "24"}),
	)
})