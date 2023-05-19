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
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/golang/mock/gomock"
	identitypb "github.com/indykite/indykite-sdk-go/gen/indykite/identity/v1beta2"
	"github.com/indykite/indykite-sdk-go/identity"
	identitym "github.com/indykite/indykite-sdk-go/test/identity/v1beta2"
	"github.com/open-policy-agent/opa/rego"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/indykite/opa-indykite-plugin/functions"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("indy.identity", func() {
	var (
		mockCtrl           *gomock.Controller
		mockIdentityClient *identitym.MockIdentityManagementAPIClient
		oldConnection      *identity.Client
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockIdentityClient = identitym.NewMockIdentityManagementAPIClient(mockCtrl)
		client, _ := identity.NewTestClient(mockIdentityClient)
		oldConnection = functions.OverrideIdentityClient(client)
	})
	AfterEach(func() {
		functions.OverrideIdentityClient(oldConnection)
	})

	It("Handle missing TokenInfo, when active = false", func() {
		mockIdentityClient.EXPECT().
			TokenIntrospect(gomock.Any(), gomock.Eq(&identitypb.TokenIntrospectRequest{Token: testAccessToken})).
			Return(&identitypb.TokenIntrospectResponse{Active: false}, nil)

		r := rego.New(rego.Query(fmt.Sprintf(`x = indy.identity("%s")`, testAccessToken)))

		ctx := context.Background()
		query, err := r.PrepareForEval(ctx)
		Ω(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Ω(err).To(Succeed())

		Ω(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
			"active": BeFalse(),
			"error":  BeNil(),
		}))
	})

	It("Handle attributes from TokenInfo when active = true", func() {
		appSpaceID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35a"
		applicationID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35b"
		customerID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35c"
		tenantID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35d"
		expireTime := time.Now()
		subjectID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35e"

		mockIdentityClient.EXPECT().
			TokenIntrospect(gomock.Any(), gomock.Eq(&identitypb.TokenIntrospectRequest{Token: testAccessToken})).
			Return(&identitypb.TokenIntrospectResponse{
				Active: true,
				TokenInfo: &identitypb.IdentityTokenInfo{
					AppSpaceId:    appSpaceID,
					ApplicationId: applicationID,
					CustomerId:    customerID,
					ExpireTime:    timestamppb.New(expireTime),
					Subject: &identitypb.DigitalTwin{
						TenantId: tenantID,
						Id:       subjectID,
					},
					TokenClaims: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"string_claim": structpb.NewStringValue("string_value"),
							"number_claim": structpb.NewNumberValue(42),
							"bool_claim":   structpb.NewBoolValue(true),
							"null_claim":   structpb.NewNullValue(),
							"map_claim": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
								"key": structpb.NewStringValue("string_value"),
							}}),
							"array_claim": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
								structpb.NewStringValue("string_value"),
							}}),
						},
					},
					SessionClaims: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"string_claim": structpb.NewStringValue("string_value"),
							"number_claim": structpb.NewNumberValue(42),
							"bool_claim":   structpb.NewBoolValue(true),
							"null_claim":   structpb.NewNullValue(),
							"map_claim": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
								"key": structpb.NewStringValue("string_value"),
							}}),
							"array_claim": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
								structpb.NewStringValue("string_value"),
							}}),
						},
					},
				},
			}, nil)

		r := rego.New(rego.Query(fmt.Sprintf(`x = indy.identity("%s")`, testAccessToken)))

		ctx := context.Background()
		query, err := r.PrepareForEval(ctx)
		Ω(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Ω(err).To(Succeed())

		Ω(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
			"active":         BeTrue(),
			"error":          BeNil(),
			"impersonatedId": Equal(""),
			"appSpaceId":     Equal(appSpaceID),
			"applicationId":  Equal(applicationID),
			"customerId":     Equal(customerID),
			"subjectId":      Equal(subjectID),
			"tenantId":       Equal(tenantID),
			"expire":         Equal(json.Number(strconv.FormatInt(expireTime.Unix(), 10))),
			"tokenClaims": MatchAllKeys(Keys{
				"string_claim": Equal("string_value"),
				"number_claim": Equal(json.Number(strconv.FormatInt(42, 10))),
				"bool_claim":   BeTrue(),
				"null_claim":   BeNil(),
				"map_claim": MatchAllKeys(Keys{
					"key": Equal("string_value"),
				}),
				"array_claim": ConsistOf("string_value"),
			}),
			"sessionClaims": MatchAllKeys(Keys{
				"string_claim": Equal("string_value"),
				"number_claim": Equal(json.Number(strconv.FormatInt(42, 10))),
				"bool_claim":   BeTrue(),
				"null_claim":   BeNil(),
				"map_claim": MatchAllKeys(Keys{
					"key": Equal("string_value"),
				}),
				"array_claim": ConsistOf("string_value"),
			}),
		}))
	})

	It("Handle gRPC client-side error response", func() {
		mockIdentityClient.EXPECT().
			TokenIntrospect(gomock.Any(), gomock.Eq(&identitypb.TokenIntrospectRequest{Token: testAccessToken})).
			Return(nil, status.Errorf(codes.Unauthenticated, "missing or invalid token"))

		r := rego.New(rego.Query(fmt.Sprintf(`x = indy.identity("%s")`, testAccessToken)))

		ctx := context.Background()
		query, err := r.PrepareForEval(ctx)
		Ω(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Ω(err).To(Succeed())

		Ω(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
			"error": MatchAllKeys(Keys{
				"message":    Not(BeEmpty()),
				"grpc_errno": Equal(json.Number(strconv.FormatInt(int64(codes.Unauthenticated), 10))),
				"grpc_error": Equal(codes.Unauthenticated.String()),
			}),
		}))
	})
})
