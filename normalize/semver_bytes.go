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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package normalize

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

// Semver versions are stored as bytea in the database. The encoding is built so that
// comparing two encodings byte by byte (which is what postgres does for bytea) yields
// the semver precedence of the versions. That keeps range queries and btree indexes
// working without a database extension.
//
// Layout:
//
//	number          = len(digits) as one byte, followed by the ascii digits
//	core            = number(major) number(minor) number(patch)
//	release         = core 0xFF
//	pre-release     = core identifier... 0x00
//	  numeric id    = 0x01 number
//	  alphanumeric  = 0x02 ascii 0x00
//	build metadata  = appended raw after the above (without the "+")
//
// Numbers never have leading zeros, so a shorter number is always the smaller one and
// numbers of equal length compare digit by digit. 0x00 ends the identifier list and sorts
// before both identifier tags, so a shorter pre-release list sorts first. 0xFF sorts after
// both tags, so a pre-release always sorts before its release.
// Build metadata has no precedence in semver. It is only kept as a trailing tie-breaker
// so that the encoding stays lossless.
const (
	semverPreReleaseEnd     byte = 0x00
	semverNumericID         byte = 0x01
	semverAlphanumericID    byte = 0x02
	semverAlphanumericIDEnd byte = 0x00
	semverRelease           byte = 0xFF
)

// SemverToBytes encodes a strict semver string (no "v" prefix, see ConvertToSemver)
// into its order preserving byte representation.
func SemverToBytes(version string) ([]byte, error) {
	if !ValidSemverRegex.MatchString(version) {
		return nil, fmt.Errorf("invalid semver: %q", version)
	}

	version, buildMetadata, _ := strings.Cut(version, "+")
	core, preRelease, hasPreRelease := strings.Cut(version, "-")

	buf := make([]byte, 0, len(version)+len(buildMetadata)+8)
	var err error
	for part := range strings.SplitSeq(core, ".") {
		if buf, err = appendSemverNumber(buf, part); err != nil {
			return nil, err
		}
	}

	if !hasPreRelease {
		buf = append(buf, semverRelease)
	} else {
		for identifier := range strings.SplitSeq(preRelease, ".") {
			if isNumericIdentifier(identifier) {
				buf = append(buf, semverNumericID)
				if buf, err = appendSemverNumber(buf, identifier); err != nil {
					return nil, err
				}
			} else {
				buf = append(buf, semverAlphanumericID)
				buf = append(buf, identifier...)
				buf = append(buf, semverAlphanumericIDEnd)
			}
		}
		buf = append(buf, semverPreReleaseEnd)
	}

	return append(buf, buildMetadata...), nil
}

// BytesToSemver decodes the output of SemverToBytes back into the semver string.
func BytesToSemver(encoded []byte) (string, error) {
	var sb strings.Builder
	sb.Grow(len(encoded))

	rest := encoded
	for i := range 3 {
		number, r, err := readSemverNumber(rest)
		if err != nil {
			return "", err
		}
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(number)
		rest = r
	}

	if len(rest) == 0 {
		return "", fmt.Errorf("invalid encoded semver: missing release marker")
	}

	if rest[0] == semverRelease {
		rest = rest[1:]
	} else {
		sb.WriteByte('-')
		for first := true; ; first = false {
			if len(rest) == 0 {
				return "", fmt.Errorf("invalid encoded semver: unterminated pre-release")
			}
			tag := rest[0]
			rest = rest[1:]
			if tag == semverPreReleaseEnd {
				break
			}
			if !first {
				sb.WriteByte('.')
			}
			switch tag {
			case semverNumericID:
				number, r, err := readSemverNumber(rest)
				if err != nil {
					return "", err
				}
				sb.WriteString(number)
				rest = r
			case semverAlphanumericID:
				end := -1
				for j, b := range rest {
					if b == semverAlphanumericIDEnd {
						end = j
						break
					}
				}
				if end == -1 {
					return "", fmt.Errorf("invalid encoded semver: unterminated identifier")
				}
				sb.Write(rest[:end])
				rest = rest[end+1:]
			default:
				return "", fmt.Errorf("invalid encoded semver: unknown identifier tag %#x", tag)
			}
		}
	}

	if len(rest) > 0 {
		sb.WriteByte('+')
		sb.Write(rest)
	}
	return sb.String(), nil
}

// Semver is a semver string that is stored in the database as its SemverToBytes encoding.
// It converts itself through driver.Valuer and sql.Scanner, which gorm and pgx (including
// CopyFrom) both use, so the go side keeps working with the plain string.
type Semver string

func (s Semver) Value() (driver.Value, error) {
	return SemverToBytes(string(s))
}

func (s *Semver) Scan(src any) error {
	encoded, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("semver: expected []byte, got %T", src)
	}
	version, err := BytesToSemver(encoded)
	if err != nil {
		return err
	}
	*s = Semver(version)
	return nil
}

// SemverPtr converts an optional version string into an optional Semver.
func SemverPtr(version *string) *Semver {
	if version == nil {
		return nil
	}
	s := Semver(*version)
	return &s
}

// String returns the version or "" for nil, so optional versions can be used as text.
func (s *Semver) String() string {
	if s == nil {
		return ""
	}
	return string(*s)
}

// StringPtr returns the version as an optional string, nil stays nil.
func (s *Semver) StringPtr() *string {
	if s == nil {
		return nil
	}
	version := string(*s)
	return &version
}

func appendSemverNumber(buf []byte, digits string) ([]byte, error) {
	if len(digits) > 255 {
		return nil, fmt.Errorf("semver number too long: %d digits", len(digits))
	}
	buf = append(buf, byte(len(digits)))
	return append(buf, digits...), nil
}

func readSemverNumber(encoded []byte) (string, []byte, error) {
	if len(encoded) == 0 {
		return "", nil, fmt.Errorf("invalid encoded semver: missing number")
	}
	length := int(encoded[0])
	if len(encoded) < 1+length {
		return "", nil, fmt.Errorf("invalid encoded semver: number truncated")
	}
	return string(encoded[1 : 1+length]), encoded[1+length:], nil
}

func isNumericIdentifier(identifier string) bool {
	for i := 0; i < len(identifier); i++ {
		if identifier[i] < '0' || identifier[i] > '9' {
			return false
		}
	}
	return true
}
