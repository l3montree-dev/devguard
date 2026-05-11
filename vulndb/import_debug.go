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
package vulndb

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
)

/*
5:47AM ERR vulndb/integrity.go:116 invalid checksum when importing table=exploits expectedCount=8523 actualCount=8531 expectedChecksum=6232333932343434376236666336666535663665393965313334633335303563 actualChecksum=3335373562623638303565326630343838356534663462636435656662633461
5:47AM ERR vulndb/integrity.go:116 invalid checksum when importing table=cve_relationships expectedCount=215759 actualCount=215788 expectedChecksum=6439313364643532363862326331373839346234343838356536316238643034 actualChecksum=3766303064303736356131643233663934343961316231366364373664376337
5:47AM ERR vulndb/integrity.go:116 invalid checksum when importing table=affected_components expectedCount=2161081 actualCount=2161314 expectedChecksum=3730363337353037646331346366346436376539383930636664643338393630 actualChecksum=3931396231656432336331393661663066343634613062343638633038376663
5:47AM ERR vulndb/integrity.go:116 invalid checksum when importing table=cves expectedCount=177924 actualCount=177937 expectedChecksum=3763393961343964323137366431336632653134373566363138373365313061 actualChecksum=3639396336643561346561343866313334656338393461323435343439316636
5:47AM ERR vulndb/integrity.go:116 invalid checksum when importing table=cve_affected_component expectedCount=9495979 actualCount=9496443 expectedChecksum=3330326465346438323864633837303139656665633963366138316538343535 actualChecksum=6564616333633034393337363539613938633833333666313933303361663438

There are MORE cves in the database after the import than expected expectedCount=177924 actualCount=177937
*/
func TestImportRC(t *testing.T) {
	// extract the vulndb.tar.zst fixture to a temp dir
	if _, err := os.Stat("vulndb-testdata-new"); os.IsNotExist(err) {
		if err := untarZstd("vulndb-new.tar.zst", "vulndb-testdata-new"); err != nil {
			t.Fatalf("could not extract vulndb testdata: %v", err)
		}
	}
	/*lastImportTime, err := time.Parse(time.RFC3339Nano, "2026-05-10T05:10:29.831137845Z")
	if err != nil {
		t.Fatalf("could not parse last import time: %v", err)
	}*/
	/*

		Okay ich habe keine Ahnung was ich hier tppe
	*/

	currentStateFile, err := os.ReadFile("prod-db-cves-full.csv")
	if err != nil {
		t.Fatalf("could not read current state file: %v", err)
	}
	// split into lines
	lines := bytes.Split(currentStateFile, []byte{'\n'})
	// remove the first line (header)
	lines = lines[1:]

	// read the whole osv.go file and check what cves we would insert right now
	osvEntries, err := readAllGobItems[OSVEntry]("vulndb-testdata-new/osv.gob")
	if err != nil {
		t.Fatalf("could not read osv gob file: %v", err)
	}

	// remove all malicious packages and components from the osvEntries, as they are not part of the RC import
	filteredOSVEntries := make([]OSVEntry, 0, len(osvEntries))
	for _, entry := range osvEntries {
		if !bytes.HasPrefix([]byte(entry.OSV.ID), []byte("MAL-")) {
			filteredOSVEntries = append(filteredOSVEntries, entry)
		}
	}
	// check what cves we would insert right now
	cves := gobOSVToVulnFilterTransformer(time.Time{}, nil)(filteredOSVEntries)

	// check which cves we would insert right now are not in the current state file
	currentStateMap := make(map[string]struct{})
	for _, line := range lines {
		// split by comma and get the first column (cve id)
		columns := bytes.Split(line, []byte{','})
		if len(columns) > 0 {
			currentStateMap[string(columns[0])] = struct{}{}
		}
	}

	newStateMap := make(map[string]struct{})
	for _, cve := range cves.CVEs {
		newStateMap[cve.CVE] = struct{}{}
	}

	// check which cves are in the currentStateMap but not in the newStateMap
	for cve := range currentStateMap {
		if _, exist := newStateMap[cve]; !exist {
			t.Logf("CVE in current state but not in new state: %s", cve)
		}
	}
	t.Fail()
}

/*
--- FAIL: TestImportRC (3.85s)
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-579f-8639-173e
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-e780-297e-3c37
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-01ac-8821-274a
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-f04c-582a-df62
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-1dc5-af13-00c1
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-7627-a361-b4d3
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-5818-1fba-950a
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-de02-7575-4370
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-37cc-2ae7-e3c8
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-34c7-ca18-1a8c
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-435f-9eb9-99cb
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-f4ca-f938-4210
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-7f2f-e83a-5508
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-879a-fe35-cf61
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state: ECHO-c9a3-95ec-f0d8
    /Users/timbastin/Desktop/l3montree/devguard/vulndb/import_test.go:88: CVE in current state but not in new state:
*/

func TestWouldBeDeleted(t *testing.T) {
	b, err := os.ReadFile("test.osv.json")
	if err != nil {
		t.Fatalf("could not read test osv file: %v", err)
	}

	// parse as osv entry
	var entry dtos.OSV
	if err := json.Unmarshal(b, &entry); err != nil {
		t.Fatalf("could not parse test osv file: %v", err)
	}

	relationships := transformer.OSVToCVERelationships(&entry)
	affectedComponentsForCVE := transformer.AffectedComponentsFromOSV(&entry)
	if len(affectedComponentsForCVE) == 0 && len(relationships) == 0 {
		t.Logf("no relationships or affected components for CVE %s", entry.ID)
	}

	cve := transformer.OSVToCVE(&entry)
	if cve.CVE == "" {
		t.Logf("could not transform OSV to CVE: %s", entry.ID)
	}
}
