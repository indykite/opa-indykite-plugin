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
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	//nolint
	testAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

func TestFunctions(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Functions Suite")
}

type matcherWrapper struct {
	matcher types.GomegaMatcher
	// This is used to save variable between calls to Matches and String in case of error
	// to be able to print better messages on failure
	actual interface{}
}

func WrapMatcher(matcher types.GomegaMatcher) gomock.Matcher {
	return &matcherWrapper{matcher: matcher}
}

func (m *matcherWrapper) Matches(x interface{}) (ok bool) {
	m.actual = x
	var err error
	if ok, err = m.matcher.Match(x); err != nil {
		ok = false
	}
	return
}

func (m *matcherWrapper) String() string {
	return fmt.Sprintf("Wrapped Gomega fail message: %s", m.matcher.FailureMessage(m.actual))
}

// EqualProto uses proto.Equal to compare actual with expected.  Equal is strict about
// types when performing comparisons.
// It is an error for both actual and expected to be nil.  Use BeNil() instead.
func EqualProto(expected protoreflect.ProtoMessage) types.GomegaMatcher {
	return &EqualProtoMatcher{
		Expected: expected,
	}
}

type EqualProtoMatcher struct {
	Expected proto.Message
}

func (matcher *EqualProtoMatcher) Match(actual interface{}) (success bool, err error) {
	if actual == nil && matcher.Expected == nil {
		// nolint
		return false, fmt.Errorf("Refusing to compare <nil> to <nil>.\nBe explicit and use BeNil() instead.  This is to avoid mistakes where both sides of an assertion are erroneously uninitialized.")
	}

	if a, ok := actual.(*anypb.Any); ok {
		var pa proto.Message
		pa, err = a.UnmarshalNew()
		if err != nil {
			return false, err
		}
		return proto.Equal(pa, matcher.Expected), nil
	}

	pa, ok := actual.(proto.Message)
	if !ok {
		return false, fmt.Errorf("Expected a proto.Message.  Got:\n%s", format.Object(actual, 1))
	}
	return proto.Equal(pa, matcher.Expected), nil
}

func (matcher *EqualProtoMatcher) FailureMessage(actual interface{}) (message string) {
	actualMessage, actualOK := actual.(proto.Message)
	if actualOK {
		op := protojson.MarshalOptions{AllowPartial: true}
		ac, _ := op.Marshal(actualMessage)
		ex, _ := op.Marshal(matcher.Expected)
		return format.MessageWithDiff(string(ac), "to equal", string(ex))
	}

	return format.Message(actual, "to equal", matcher.Expected)
}

func (matcher *EqualProtoMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	actualMessage, actualOK := actual.(proto.Message)
	if actualOK {
		op := protojson.MarshalOptions{AllowPartial: true}
		ac, _ := op.Marshal(actualMessage)
		ex, _ := op.Marshal(matcher.Expected)
		return format.MessageWithDiff(string(ac), "not to equal", string(ex))
	}
	return format.Message(actual, "not to equal", matcher.Expected)
}
