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

package statemachine

import (
	"fmt"
	"slices"
)

const (
	VisibilityDraft     = "draft"
	VisibilityPublic    = "public"
	VisibilityWithdrawn = "withdrawn"
)

var validTransitions = map[string][]string{
	VisibilityPublic:    {VisibilityDraft},
	VisibilityWithdrawn: {VisibilityPublic},
}

func CheckStateTransition(currentVisibility string, newVisibility string) error {
	if states, ok := validTransitions[newVisibility]; ok && slices.Contains(states, currentVisibility) {
		return nil
	}
	return fmt.Errorf("invalid state transfer")
}

func CanDelete(currentVisibility string) error {
	if currentVisibility == VisibilityDraft {
		return nil
	}
	return fmt.Errorf("advisory can not be deleted")
}
