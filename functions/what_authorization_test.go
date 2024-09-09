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
	objects "github.com/indykite/indykite-sdk-go/gen/indykite/objects/v1beta1"
	"github.com/indykite/indykite-sdk-go/test"
	authorizationm "github.com/indykite/indykite-sdk-go/test/authorization/v1beta1"
	"github.com/open-policy-agent/opa/rego"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/indykite/opa-indykite-plugin/functions"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("indy.what_authorized", func() {
	var (
		mockCtrl                *gomock.Controller
		mockAuthorizationClient *authorizationm.MockAuthorizationAPIClient
		oldConnection           *authorization.Client
		idFn                    = func(resource interface{}) string {
			switch r := resource.(type) {
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
			mockAuthorizationClient.EXPECT().WhatAuthorized(
				gomock.Any(),
				WrapMatcher(EqualProto(&authorizationpb.WhatAuthorizedRequest{
					Subject: c.reqSubject,
					ResourceTypes: []*authorizationpb.WhatAuthorizedRequest_ResourceType{
						{Type: "TypeOne", Actions: []string{"READ"}},
						{Type: "TypeTwo"},
					},
					InputParams: map[string]*authorizationpb.InputParam{
						"string":  {Value: &authorizationpb.InputParam_StringValue{StringValue: "42"}},
						"boolean": {Value: &authorizationpb.InputParam_BoolValue{BoolValue: true}},
						"double":  {Value: &authorizationpb.InputParam_DoubleValue{DoubleValue: 4.2}},
						"integer": {Value: &authorizationpb.InputParam_IntegerValue{IntegerValue: 42}},
					},
					PolicyTags: []string{"42"},
				})),
			).Return(&authorizationpb.WhatAuthorizedResponse{
				DecisionTime: c.respDecisionTime,
				Decisions: map[string]*authorizationpb.WhatAuthorizedResponse_ResourceType{
					"TypeOne": {
						Actions: map[string]*authorizationpb.WhatAuthorizedResponse_Action{
							"READ": {
								Resources: []*authorizationpb.WhatAuthorizedResponse_Resource{
									{ExternalId: "res1"},
									{ExternalId: "res2"},
								},
							},
						},
					},
					"TypeTwo": {
						Actions: map[string]*authorizationpb.WhatAuthorizedResponse_Action{
							"WRITE": {
								Resources: []*authorizationpb.WhatAuthorizedResponse_Resource{
									{ExternalId: "res1"},
									{ExternalId: "res2"},
								},
							},
						},
					},
				},
			}, nil)

			r := rego.New(rego.Query(`x = indy.what_authorized(` + c.regoParam1 + `,[{"type": "TypeOne", "actions": ["READ"]},{"type": "TypeTwo"}], {"string": {"string_value":"42"}, "integer": {"integer_value":42}, "double": {"double_value":4.2}, "boolean": {"bool_value":true}}, ["42"])`)) //nolint:lll

			ctx := context.Background()
			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(err).To(Succeed())
			Expect(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
				"error":        BeNil(),
				"decisionTime": c.decisionTimeMatcher,
				"decisions": MatchAllKeys(Keys{
					"TypeOne": MatchAllKeys(Keys{
						"READ": MatchAllElements(idFn, Elements{
							"res1": MatchAllKeys(Keys{
								"externalId": Equal("res1"),
							}),
							"res2": MatchAllKeys(Keys{
								"externalId": Equal("res2"),
							}),
						}),
					}),
					"TypeTwo": MatchAllKeys(Keys{
						"WRITE": MatchAllElements(idFn, Elements{
							"res1": MatchAllKeys(Keys{
								"externalId": Equal("res1"),
							}),
							"res2": MatchAllKeys(Keys{
								"externalId": Equal("res2"),
							}),
						}),
					}),
				}),
			}))
		},
		Entry("Access Token", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_AccessToken{
					AccessToken: testAccessToken,
				},
			},
			respDecisionTime:    timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
			respTTL:             durationpb.New(time.Minute * 90),
			decisionTimeMatcher: BeEquivalentTo("1645543102"), // All numbers are json.Number ie string
			ttlMatcher:          BeEquivalentTo("5400"),
			regoParam1:          `{"id": "` + testAccessToken + `"}`,
		}),
		Entry("Access Token - with type", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_AccessToken{
					AccessToken: testAccessToken,
				},
			},
			respDecisionTime:    timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
			respTTL:             durationpb.New(time.Minute * 90),
			decisionTimeMatcher: BeEquivalentTo("1645543102"), // All numbers are json.Number ie string
			ttlMatcher:          BeEquivalentTo("5400"),
			regoParam1:          `{"id": "` + testAccessToken + `", "subjectType": "token"}`,
		}),
		Entry("DigitalTwin", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_DigitalTwinId{
					DigitalTwinId: &authorizationpb.DigitalTwin{
						Id: "gid:AAAAFezuHiJHiUeRjrIJV8k3oKo",
					},
				},
			},
			// Test also nil values
			respDecisionTime:    nil,
			respTTL:             nil,
			decisionTimeMatcher: BeEquivalentTo("0"),
			ttlMatcher:          BeEquivalentTo("0"),
			regoParam1:          `{"id": "gid:AAAAFezuHiJHiUeRjrIJV8k3oKo", "subjectType": "id"}`,
		}),
		Entry("DigitalTwin property", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_DigitalTwinProperty{
					DigitalTwinProperty: &authorizationpb.Property{
						Type:  "email",
						Value: objects.String("sam@sung.com"),
					},
				},
			},
			// Test also nil values
			respDecisionTime:    nil,
			respTTL:             nil,
			decisionTimeMatcher: BeEquivalentTo("0"),
			ttlMatcher:          BeEquivalentTo("0"),
			regoParam1:          `{"id": "sam@sung.com", "subjectType": "property", "property": "email"}`,
		}),
		Entry("DigitalTwin externalID", &dtIDCase{
			reqSubject: &authorizationpb.Subject{
				Subject: &authorizationpb.Subject_ExternalId{
					ExternalId: &authorizationpb.ExternalID{
						Type:       "Person",
						ExternalId: "some-external-id",
					},
				},
			},
			// Test also nil values
			respDecisionTime:    nil,
			respTTL:             nil,
			decisionTimeMatcher: BeEquivalentTo("0"),
			ttlMatcher:          BeEquivalentTo("0"),
			regoParam1:          `{"id": "some-external-id", "subjectType": "external_id", "type": "Person"}`,
		}),
	)

	//nolint:lll
	DescribeTable("Invalid input arguments - gRPC error",
		func(regoParams string, errorMessage string, originMessage string) {
			q := `x = indy.what_authorized(` + regoParams + `)`
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
		Entry("Request validation fail", `{"id": "a"}, [{"type": "Type", "actions": ["READ"]}], {}, []`,
			"unable to call WhatAuthorized client endpoint", "AccessToken: value length must be at least 20 runes"),
		Entry("Invalid access token", `{"id": "aaaaaaaaaaaaaaaaaaaa"}, [{"type": "Type", "actions": ["READ"]}], {}, []`,
			"invalid token format", "invalid JWT"),
		Entry("Empty resource_references", `{"id": "`+testAccessToken+`"}, [], {}, []`,
			"unable to call WhatAuthorized client endpoint",
			"invalid WhatAuthorizedRequest.ResourceTypes: value must contain between 1 and 10 items, inclusive"),
		Entry("Invalid digital twin", `{"id": "abc", "subjectType": "id"}, [{"type": "Type", "actions": ["READ"]}], {}, []`,
			"unable to call WhatAuthorized client endpoint",
			"invalid DigitalTwin.Id: value length must be between 27 and 100 runes"),
		Entry("Invalid propertyType", `{"id": "", "subjectType": "property", "property": ""}, [{"type": "Type", "actions": ["READ"]}, {"type": "Type", "actions": ["READ"]}], {}, []`,
			"unable to call WhatAuthorized client endpoint",
			"invalid Property.Type: value length must be between 2 and 20 runes"),
	)

	It("Service backend error", func() {
		ctx := context.Background()
		mockAuthorizationClient.EXPECT().
			WhatAuthorized(gomock.Any(), gomock.Any()).
			Times(2).
			Return(nil, status.Error(codes.Internal, "oops"))

		// With StrictBuiltinErrors
		r := rego.New(
			rego.Query(`x = indy.what_authorized({"id": "`+testAccessToken+`"}, [{"type": "Type", "actions": ["READ"]}], {}, [])`), //nolint:lll
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.what_authorized: client error: code = Internal desc = oops")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.what_authorized({"id": "` + testAccessToken + `"}, [{"type": "Type", "actions": ["READ"]}], {}, [])`)) //nolint:lll

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
			rego.Query(`x = indy.what_authorized({"id": "`+testAccessToken+`"}, [{"type": "Type", "actions": ["READ"]}], {}, [])`), //nolint:lll
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.what_authorized: missing endpoint")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.what_authorized({"id": "` + testAccessToken + `"}, [{"type": "Type", "actions": ["READ"]}], {}, [])`)) //nolint:lll

		query, err = r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err = query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(Succeed())
	})
	DescribeTable("Testing options",
		func(regoOptions string, inputParams map[string]*authorizationpb.InputParam, policyTags []string) {
			request := &authorizationpb.WhatAuthorizedRequest{
				Subject: &authorizationpb.Subject{
					Subject: &authorizationpb.Subject_AccessToken{
						AccessToken: testAccessToken,
					},
				},
				ResourceTypes: []*authorizationpb.WhatAuthorizedRequest_ResourceType{
					{Type: "Type", Actions: []string{"READ"}},
				},
				InputParams: inputParams,
				PolicyTags:  policyTags,
			}

			mockAuthorizationClient.EXPECT().WhatAuthorized(
				gomock.Any(),
				WrapMatcher(test.EqualProto(request)),
			).Return(&authorizationpb.WhatAuthorizedResponse{
				DecisionTime: timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
				Decisions: map[string]*authorizationpb.WhatAuthorizedResponse_ResourceType{
					"Type": {
						Actions: map[string]*authorizationpb.WhatAuthorizedResponse_Action{
							"READ": {
								Resources: []*authorizationpb.WhatAuthorizedResponse_Resource{
									{ExternalId: "res1"},
								},
							},
						},
					},
				},
			}, nil)

			q := `x = indy.what_authorized({"id": "` + testAccessToken + `"},[{"type": "Type", "actions": ["READ"]}],` + regoOptions + `)` // nolint:lll
			r := rego.New(rego.Query(q))

			ctx := context.Background()
			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(err).To(Succeed())
			Expect(rs[0].Bindings["x"]).To(Not(BeNil()))
		},
		Entry("Empty options", `{}, []`, nil, nil),
		Entry("inputParams - String param", `{ "string": {"string_value":"42"} }, []`,
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
		Entry("policyTags - empty array", `{}, []`, nil, nil),
		Entry("policyTags - two values in array", `{}, ["42", "24"]`, nil, []string{"42", "24"}),
	)
})
