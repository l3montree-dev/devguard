# Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

#!/bin/bash

# Usage: ./bump_version.sh patch|minor|major

if [ -z "$1" ]; then
  echo "No version bump type provided. Usage: ./bump_version.sh patch|minor|major"
  exit 1
fi

BUMP_TYPE=$1

# Extract current version from Chart.yaml
CURRENT_VERSION=$(grep '^version:' charts/devguard/Chart.yaml | awk '{print $2}')
echo "Current version: $CURRENT_VERSION"

# Use semver tool to get the new version
NEW_VERSION=$(semver -i "$CURRENT_VERSION" "$BUMP_TYPE")
echo "New version: $NEW_VERSION"

# Update Chart.yaml with the new version
sed -i '' -e "s/version: .*/version: $NEW_VERSION/" charts/devguard/Chart.yaml
sed -i '' -e "s/appVersion: .*/appVersion: $NEW_VERSION/" charts/devguard/Chart.yaml

# Commit and tag the new version
git add .
git commit -m "Bump version to $NEW_VERSION"
git tag "v$NEW_VERSION"
