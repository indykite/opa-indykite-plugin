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

package utilities

import (
	"errors"

	"github.com/open-policy-agent/opa/ast"
	"github.com/pborman/uuid"
)

var (
	// ErrInvalidUUID specify error message when UUID does not satisfy RFC4122.
	ErrInvalidUUID = errors.New("invalid UUID, must be valid RFC4122 variant")
	// ErrNonStringTerm specify error message when term is not ast.String.
	ErrNonStringTerm = errors.New("invalid term value, must be ast.String")
)

// GetOptionalUUID converts bytes into UUID string representation or empty string if nil passed.
// Returns error if bytes are not valid RFC4122 UUID.
func GetOptionalUUID(binaryUUID []byte) (string, error) {
	if len(binaryUUID) == 0 {
		return "", nil
	}

	uuidObj := uuid.UUID(binaryUUID)
	if uuidObj.Variant() != uuid.RFC4122 {
		return "", ErrInvalidUUID
	}
	return uuidObj.String(), nil
}

// ParseUUID takes string and tries to parse as RFC4122 UUID.
func ParseUUID(strUUID string) (uuid.UUID, error) {
	id := uuid.Parse(strUUID)
	if id.Variant() != uuid.RFC4122 {
		return nil, ErrInvalidUUID
	}
	return id, nil
}

// ParseTermAsUUID takes ast.Term and tries to parse as RFC4122 UUID.
func ParseTermAsUUID(term *ast.Term) (uuid.UUID, error) {
	if term == nil {
		return nil, errors.New("missing value")
	}

	// When casting fails, termStr will contain empty string
	termStr, ok := term.Value.(ast.String)
	if !ok {
		return nil, ErrNonStringTerm
	}
	dtUUID, err := ParseUUID(string(termStr))
	if err != nil {
		return nil, err
	}

	return dtUUID, nil
}
