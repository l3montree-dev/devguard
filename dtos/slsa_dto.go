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

package dtos

const SLSAProvenanceV1PredicateType = "https://slsa.dev/provenance/v1"
const SLSACIWorkflowBuildType = "https://devguard.org/slsa/build-types/ci-workflow/v1"

// SLSASelfSignedBuilderID marks provenance signed with a devguard token instead of by DevGuard - no build platform verified it (SLSA Build L1)
const SLSASelfSignedBuilderID = "https://devguard.org/slsa/builders/self-signed/v1"
