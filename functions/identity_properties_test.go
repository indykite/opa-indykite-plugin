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
	objects "github.com/indykite/indykite-sdk-go/gen/indykite/objects/v1beta1"
	"github.com/indykite/indykite-sdk-go/identity"
	identitym "github.com/indykite/indykite-sdk-go/test/identity/v1beta2"
	"github.com/open-policy-agent/opa/rego"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/indykite/opa-indykite-plugin/functions"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("indy.identity_properties", func() {
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

	It("Handle attributes from TokenInfo and Properties", func() {
		appSpaceID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35a"
		applicationID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35b"
		customerID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35c"
		tenantID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35d"
		expireTime := time.Now()
		subjectID := "gid:AAAAA-l_3DSuyE6Sm5nRSyDv35e"

		mockIdentityClient.EXPECT().
			GetDigitalTwin(
				gomock.Any(),
				WrapMatcher(PointTo(MatchFields(IgnoreExtras, Fields{
					"Id": PointTo(MatchFields(IgnoreExtras, Fields{"Filter": PointTo(MatchFields(IgnoreExtras, Fields{
						"AccessToken": Equal(testAccessToken),
					}))})),
					"Properties": ConsistOf(
						PointTo(MatchFields(IgnoreExtras, Fields{"Definition": PointTo(MatchFields(IgnoreExtras, Fields{
							"Property": Equal("arr"),
						}))})),
						PointTo(MatchFields(IgnoreExtras, Fields{"Definition": PointTo(MatchFields(IgnoreExtras, Fields{
							"Property": Equal("email"),
						}))})),
					)}))),
			).
			Return(&identitypb.GetDigitalTwinResponse{
				DigitalTwin: &identitypb.DigitalEntity{
					DigitalTwin: &identitypb.DigitalTwin{
						Id:       subjectID,
						TenantId: tenantID,
					},
					Properties: []*identitypb.Property{
						{
							Id:         "af54",
							Definition: &identitypb.PropertyDefinition{Property: "arr", Context: "ctx", Type: "IOT"},
							Meta: &identitypb.PropertyMetadata{
								Primary:          true,
								AssuranceLevel:   identitypb.AssuranceLevel_ASSURANCE_LEVEL_HIGH,
								Issuer:           "google.com",
								Verifier:         "my-app-id",
								VerificationTime: timestamppb.New(time.Date(2020, 8, 8, 8, 8, 8, 0, time.UTC)),
							},
							Value: &identitypb.Property_ObjectValue{ObjectValue: &objects.Value{
								Value: &objects.Value_ArrayValue{ArrayValue: &objects.ArrayValue{
									Values: []*objects.Value{
										objects.Bool(true),
										objects.Float64(45.55736),
										objects.String("some-text"),
									},
								}},
							}},
						},
						{
							Id:         "45a6",
							Definition: &identitypb.PropertyDefinition{Property: "email"},
							Meta: &identitypb.PropertyMetadata{
								AssuranceLevel: identitypb.AssuranceLevel_ASSURANCE_LEVEL_LOW,
							},
							Value: &identitypb.Property_ObjectValue{ObjectValue: objects.String("mail@example.com")},
						},
					},
				},
				TokenInfo: &identitypb.IdentityTokenInfo{
					AppSpaceId:    appSpaceID,
					ApplicationId: applicationID,
					CustomerId:    customerID,
					ExpireTime:    timestamppb.New(expireTime),
					Subject: &identitypb.DigitalTwin{
						TenantId: tenantID,
						Id:       subjectID,
					},
				},
			}, nil)

		r := rego.New(rego.Query(fmt.Sprintf(`x = indy.identity_properties("%s", ["email", "arr"])`, testAccessToken)))

		ctx := context.Background()
		query, err := r.PrepareForEval(ctx)
		Ω(err).To(Succeed())

		rs, err := query.Eval(ctx)
		Ω(err).To(Succeed())

		Ω(rs[0].Bindings["x"]).To(MatchAllKeys(Keys{
			"error": BeNil(),
			"properties": ConsistOf(
				MatchAllKeys(Keys{
					"id": Equal("45a6"),
					"definition": MatchAllKeys(
						Keys{"context": BeEmpty(), "property": Equal("email"), "type": BeEmpty()}),
					"meta": MatchAllKeys(Keys{
						"assuranceLevel":   Equal(json.Number("1")),
						"issuer":           BeEmpty(),
						"primary":          BeFalse(),
						"verificationTime": BeNil(),
						"verifier":         BeEmpty(),
					}),
					"value": Equal("mail@example.com"),
				}),
				MatchAllKeys(Keys{
					"id": Equal("af54"),
					"definition": MatchAllKeys(
						Keys{"context": Equal("ctx"), "property": Equal("arr"), "type": Equal("IOT")}),
					"meta": MatchAllKeys(Keys{
						"assuranceLevel":   Equal(json.Number("3")),
						"issuer":           Equal("google.com"),
						"primary":          BeTrue(),
						"verificationTime": Equal("2020-08-08T08:08:08Z"),
						"verifier":         Equal("my-app-id"),
					}),
					"value": ConsistOf(BeTrue(), BeEquivalentTo("45.55736"), Equal("some-text")),
				}),
			),
			"token_info": MatchAllKeys(Keys{
				"active":         BeTrue(),
				"impersonatedId": Equal(""),
				"appSpaceId":     Equal(appSpaceID),
				"applicationId":  Equal(applicationID),
				"customerId":     Equal(customerID),
				"subjectId":      Equal(subjectID),
				"tenantId":       Equal(tenantID),
				"expire":         Equal(json.Number(strconv.FormatInt(expireTime.Unix(), 10))),
				"tokenClaims":    Equal(map[string]interface{}{}),
				"sessionClaims":  Equal(map[string]interface{}{}),
			}),
		}))
	})

	It("Handle gRPC client-side error response", func() {
		mockIdentityClient.EXPECT().
			GetDigitalTwin(
				gomock.Any(),
				WrapMatcher(PointTo(MatchFields(IgnoreExtras, Fields{
					"Id": PointTo(MatchFields(IgnoreExtras, Fields{"Filter": PointTo(MatchFields(IgnoreExtras, Fields{
						"AccessToken": Equal(testAccessToken),
					}))})),
					"Properties": ConsistOf(
						PointTo(MatchFields(IgnoreExtras, Fields{"Definition": PointTo(MatchFields(IgnoreExtras, Fields{
							"Property": Equal("email"),
						}))})),
					)}))),
			).
			Return(nil, status.Errorf(codes.Unauthenticated, "missing or invalid token"))

		r := rego.New(rego.Query(fmt.Sprintf(`x = indy.identity_properties("%s", ["email"])`, testAccessToken)))

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
