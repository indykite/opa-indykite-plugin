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
	identitypb "github.com/indykite/jarvis-sdk-go/gen/indykite/identity/v1beta1"
	authorizationm "github.com/indykite/jarvis-sdk-go/test/authorization/v1beta1"
	"github.com/open-policy-agent/opa/rego"
	"github.com/pborman/uuid"
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
		reqSubject          *identitypb.DigitalTwinIdentifier
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
					Actions: []string{"READ"},
					Resources: []*authorizationpb.IsAuthorizedRequest_Resource{
						{Id: "res1", Label: "Label"},
						{Id: "res2", Label: "Label"},
					},
				})),
			).Return(&authorizationpb.IsAuthorizedResponse{
				DecisionTime: c.respDecisionTime,
				Decisions: map[string]*authorizationpb.AuthorizationDecision{
					"res1": {AllowAction: map[string]bool{"READ": true}},
					"res2": {AllowAction: map[string]bool{"READ": true}},
				},
			}, nil)

			r := rego.New(rego.Query(
				`x = indy.is_authorized(` + c.regoParam1 + `, ["READ"], [{"id": "res1", "label": "Label"}, {"id": "res2", "label": "Label"}])`)) //nolint:lll

			ctx := context.Background()
			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(err).To(Succeed())

			Expect(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
				"error":         BeNil(),
				"decision_time": c.decisionTimeMatcher,
				"decisions": MatchAllKeys(Keys{
					"res1": MatchAllKeys(Keys{
						"allow_actions": MatchAllKeys(Keys{
							"READ": Equal(true),
						}),
					}),
					"res2": MatchAllKeys(Keys{
						"allow_actions": MatchAllKeys(Keys{
							"READ": Equal(true),
						}),
					}),
				}),
			}))
		},
		Entry("Access Token", &dtIDCase{
			reqSubject: &identitypb.DigitalTwinIdentifier{Filter: &identitypb.DigitalTwinIdentifier_AccessToken{
				AccessToken: testAccessToken,
			}},
			respDecisionTime:    timestamppb.New(time.Date(2022, 02, 22, 15, 18, 22, 0, time.UTC)),
			respTTL:             durationpb.New(time.Minute * 90),
			decisionTimeMatcher: BeEquivalentTo("1645543102"), // All numbers are json.Number ie string
			ttlMatcher:          BeEquivalentTo("5400"),
			regoParam1:          `"` + testAccessToken + `"`,
		}),
		Entry("DigitalTwin", &dtIDCase{
			reqSubject: &identitypb.DigitalTwinIdentifier{Filter: &identitypb.DigitalTwinIdentifier_DigitalTwin{
				DigitalTwin: &identitypb.DigitalTwin{
					Id:       uuid.Parse("86ee93b8-7a12-4101-a1d0-5a2d8186bf4f"),
					TenantId: uuid.Parse("915cd179-239a-42dd-8202-f2213f3b9ffd"),
				},
			}},
			// Test also nil values
			respDecisionTime:    nil,
			respTTL:             nil,
			decisionTimeMatcher: BeEquivalentTo("0"),
			ttlMatcher:          BeEquivalentTo("0"),
			regoParam1:          `{"digital_twin_id": "86ee93b8-7a12-4101-a1d0-5a2d8186bf4f", "tenant_id": "915cd179-239a-42dd-8202-f2213f3b9ffd"}`, // nolint:lll
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
		Entry("Request validation fail", `"a", ["READ"], [{"id": "res1", "label": "Label"}, {"id": "res2", "label": "Label"}]`,
			"unable to call IsAuthorized client endpoint", "AccessToken: value length must be at least 20 runes"),
		Entry("Invalid access token", `"aaaaaaaaaaaaaaaaaaaa", ["READ"], [{"id": "res1", "label": "Label"}, {"id": "res2", "label": "Label"}]`,
			"invalid token format", "failed to parse token: invalid character 'a' looking for beginning of value"),
		Entry("Too many actions", `"`+testAccessToken+`", ["READ", "WRITE"], [{"id": "res1", "label": "Label"}, {"id": "res2", "label": "Label"}]`,
			"unable to call IsAuthorized client endpoint",
			"invalid IsAuthorizedRequest.Actions: value must contain exactly 1 item(s)"),
		Entry("Empty actions", `"`+testAccessToken+`", [], [{"id": "res1", "label": "Label"}, {"id": "res2", "label": "Label"}]`,
			"unable to call IsAuthorized client endpoint",
			"invalid IsAuthorizedRequest.Actions: value must contain exactly 1 item(s)"),
		Entry("Empty resource_references", `"`+testAccessToken+`", ["READ"], []`,
			"unable to call IsAuthorized client endpoint",
			"invalid IsAuthorizedRequest.Resources: value must contain between 1 and 32 items, inclusive"),
	)

	DescribeTable("Invalid input arguments - builtin error",
		func(regoParams string, errorMatcher OmegaMatcher) {
			q := `x = indy.is_authorized(` + regoParams + `, ["READ"], [{"id": "res1", "label": "Label"}, {"id": "res2", "label": "Label"}])` //nolint:lll
			ctx := context.Background()

			// With StrictBuiltinErrors
			r := rego.New(rego.Query(q), rego.StrictBuiltinErrors(true))
			query, err := r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err := query.Eval(ctx)
			Expect(rs).To(HaveLen(0))
			Expect(err).To(errorMatcher)

			// Verify that, without StrictBuiltinErrors error is nil and response too
			r = rego.New(rego.Query(q))
			query, err = r.PrepareForEval(ctx)
			Expect(err).To(Succeed())

			rs, err = query.Eval(ctx)
			Expect(rs).To(HaveLen(0))
			Expect(err).To(Succeed())
		},
		Entry("Invalid digital twin", `{"digital_twin_id": "22", "tenant_id": ""}`, MatchError(ContainSubstring(
			"indy.is_authorized: operand 1 digital_twin_id: invalid UUID, must be valid RFC4122 variant"))),
		Entry("Invalid tenant_id", `{"digital_twin_id": "6928fa19-f0e7-4e12-9771-73dce603cf41", "tenant_id": ""}`,
			MatchError(ContainSubstring(
				"indy.is_authorized: operand 1 tenant_id: invalid UUID, must be valid RFC4122 variant",
			))),
	)

	It("Service backend error", func() {
		ctx := context.Background()
		mockAuthorizationClient.EXPECT().
			IsAuthorized(gomock.Any(), gomock.Any()).
			Times(2).
			Return(nil, status.Error(codes.Internal, "oops"))

		// With StrictBuiltinErrors
		r := rego.New(
			rego.Query(`x = indy.is_authorized("`+testAccessToken+`", ["READ"], [{"id": "res1", "label": "Label"}])`),
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.is_authorized: client error: code = Internal desc = oops")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.is_authorized("` + testAccessToken + `", ["READ"], [{"id": "res1", "label": "Label"}])`)) //nolint:lll

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
			rego.Query(`x = indy.is_authorized("`+testAccessToken+`", ["READ"], [{"id": "res1", "label": "Label"}])`),
			rego.StrictBuiltinErrors(true),
		)

		query, err := r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(MatchError(ContainSubstring("indy.is_authorized: missing endpoint")))

		// Verify that, without StrictBuiltinErrors error is nil and response too
		r = rego.New(rego.Query(`x = indy.is_authorized("` + testAccessToken + `", ["READ"], [{"id": "res1", "label": "Label"}])`)) //nolint:lll

		query, err = r.PrepareForEval(ctx)
		Expect(err).To(Succeed())

		rs, err = query.Eval(ctx)
		Expect(rs).To(HaveLen(0))
		Expect(err).To(Succeed())
	})
})
