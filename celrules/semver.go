// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package celrules

import (
	"fmt"
	"reflect"

	"github.com/Masterminds/semver"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

var semverType = cel.ObjectType("devguard.Semver", traits.ComparerType)

type semverVal struct {
	version *semver.Version
}

func (v semverVal) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(v.version).AssignableTo(typeDesc) {
		return v.version, nil
	}
	return nil, fmt.Errorf("unsupported conversion from semver to %v", typeDesc)
}

func (v semverVal) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case semverType:
		return v
	case types.TypeType:
		return semverType
	case types.StringType:
		return types.String(v.version.String())
	}
	return types.NewErr("unsupported conversion from semver to %s", typeVal.TypeName())
}

func (v semverVal) Equal(other ref.Val) ref.Val {
	o, ok := other.(semverVal)
	if !ok {
		return types.False
	}
	return types.Bool(v.version.Equal(o.version))
}

func (v semverVal) Compare(other ref.Val) ref.Val {
	o, ok := other.(semverVal)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}
	return types.Int(v.version.Compare(o.version))
}

func (v semverVal) Type() ref.Type {
	return semverType
}

func (v semverVal) Value() any {
	return v.version
}

var semverFields = map[string]*types.FieldType{
	"major":      semverField(types.IntType, func(v *semver.Version) any { return int64(v.Major()) }),
	"minor":      semverField(types.IntType, func(v *semver.Version) any { return int64(v.Minor()) }),
	"patch":      semverField(types.IntType, func(v *semver.Version) any { return int64(v.Patch()) }),
	"prerelease": semverField(types.StringType, func(v *semver.Version) any { return v.Prerelease() }),
}

func semverField(fieldType *types.Type, get func(v *semver.Version) any) *types.FieldType {
	return &types.FieldType{
		Type:  fieldType,
		IsSet: func(target any) bool { _, ok := target.(*semver.Version); return ok },
		GetFrom: func(target any) (any, error) {
			v, ok := target.(*semver.Version)
			if !ok {
				return nil, fmt.Errorf("expected a semver value, got %T", target)
			}
			return get(v), nil
		},
	}
}

// semverTypeProvider makes the fields of semver values known to the type checker, so semver("v1.2.3").minor compiles
type semverTypeProvider struct {
	*types.Registry
}

func (p semverTypeProvider) FindStructType(structType string) (*types.Type, bool) {
	if structType == semverType.TypeName() {
		return types.NewTypeTypeWithParam(semverType), true
	}
	return p.Registry.FindStructType(structType)
}

func (p semverTypeProvider) FindStructFieldNames(structType string) ([]string, bool) {
	if structType == semverType.TypeName() {
		return []string{"major", "minor", "patch", "prerelease"}, true
	}
	return p.Registry.FindStructFieldNames(structType)
}

func (p semverTypeProvider) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	if structType == semverType.TypeName() {
		field, ok := semverFields[fieldName]
		return field, ok
	}
	return p.Registry.FindStructFieldType(structType, fieldName)
}

// semverLib adds semver(string), isSemver(string), the relational operators and the fields major, minor, patch and prerelease for semver values.
// a leading "v" is accepted, so tags like "v1.2.3" work as is.
func semverLib() ([]cel.EnvOption, error) {
	registry, err := types.NewRegistry()
	if err != nil {
		return nil, err
	}
	semverArgs := []*cel.Type{semverType, semverType}
	return []cel.EnvOption{
		cel.CustomTypeProvider(semverTypeProvider{Registry: registry}),
		cel.Function("semver",
			cel.Overload("semver_string", []*cel.Type{cel.StringType}, semverType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					s, ok := arg.Value().(string)
					if !ok {
						return types.NewErr("semver: invalid argument: %v", arg)
					}
					version, err := semver.NewVersion(s)
					if err != nil {
						return types.NewErr("semver: %q is not a valid semantic version", s)
					}
					return semverVal{version: version}
				}),
			),
		),
		cel.Function("isSemver",
			cel.Overload("isSemver_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					s, ok := arg.Value().(string)
					if !ok {
						return types.NewErr("isSemver: invalid argument: %v", arg)
					}
					_, err := semver.NewVersion(s)
					return types.Bool(err == nil)
				}),
			),
		),
		cel.Function(operators.Less,
			cel.Overload(overloads.LessString+"_semver", semverArgs, cel.BoolType)),
		cel.Function(operators.LessEquals,
			cel.Overload(overloads.LessEqualsString+"_semver", semverArgs, cel.BoolType)),
		cel.Function(operators.Greater,
			cel.Overload(overloads.GreaterString+"_semver", semverArgs, cel.BoolType)),
		cel.Function(operators.GreaterEquals,
			cel.Overload(overloads.GreaterEqualsString+"_semver", semverArgs, cel.BoolType)),
	}, nil
}
