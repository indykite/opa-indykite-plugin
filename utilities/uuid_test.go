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
	"github.com/open-policy-agent/opa/ast"
	"github.com/pborman/uuid"

	"github.com/indykite/opa-indykite-plugin/utilities"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("uuid", func() {
	DescribeTable("GetOptionalUUID",
		func(binaryUUID []byte, resultMatcher, errMatcher OmegaMatcher) {
			str, err := utilities.GetOptionalUUID(binaryUUID)
			Expect(str).To(resultMatcher)
			Expect(err).To(errMatcher)
		},
		Entry("nil value", nil, Equal(""), Succeed()),
		Entry("Empty array", make([]byte, 0), Equal(""), Succeed()),
		Entry("Invalid value", []byte{122, 123}, Equal(""), MatchError(utilities.ErrInvalidUUID)),
		Entry("Valid value", []byte(uuid.Parse("7d9863b7-a75a-423f-b9df-c007ee3f70cd")),
			Equal("7d9863b7-a75a-423f-b9df-c007ee3f70cd"), Succeed()),
	)

	DescribeTable("ParseUUID",
		func(strValue string, resultMatcher, errMatcher OmegaMatcher) {
			str, err := utilities.ParseUUID(strValue)
			Expect(str).To(resultMatcher)
			Expect(err).To(errMatcher)
		},
		Entry("empty value", "", BeNil(), MatchError(utilities.ErrInvalidUUID)),
		Entry("invalid value", "00112233", BeNil(), MatchError(utilities.ErrInvalidUUID)),
		Entry("null UUID", uuid.NIL.String(), BeNil(), MatchError(utilities.ErrInvalidUUID)),
		Entry("valid UUID", "e32cf9f0-21fd-4026-9a92-f121f50218e5",
			BeEquivalentTo(uuid.Parse("e32cf9f0-21fd-4026-9a92-f121f50218e5")), Succeed()),
	)

	DescribeTable("ParseTermAsUUID",
		func(strValue *ast.Term, resultMatcher, errMatcher OmegaMatcher) {
			str, err := utilities.ParseTermAsUUID(strValue)
			Expect(str).To(resultMatcher)
			Expect(err).To(errMatcher)
		},
		Entry("nil term", nil, BeNil(), MatchError(ContainSubstring("missing value"))),
		Entry("integer term", ast.IntNumberTerm(123), BeNil(), MatchError(utilities.ErrNonStringTerm)),
		Entry("object term", ast.ObjectTerm([2]*ast.Term{ast.StringTerm("a"), ast.BooleanTerm(false)}),
			BeNil(), MatchError(utilities.ErrNonStringTerm)),
		Entry("null UUID", ast.StringTerm(uuid.NIL.String()), BeNil(), MatchError(utilities.ErrInvalidUUID)),
		Entry("invalid UUID", ast.StringTerm("00112233"), BeNil(), MatchError(utilities.ErrInvalidUUID)),
		Entry("valid UUID", ast.StringTerm("380f9dfb-9f62-48e9-9b2d-378959cb0fcf"),
			BeEquivalentTo(uuid.Parse("380f9dfb-9f62-48e9-9b2d-378959cb0fcf")), Succeed()),
	)
})
