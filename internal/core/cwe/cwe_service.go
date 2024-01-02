package cwe

import (
	"encoding/xml"
	"io"
	"os"
)

func parseCWEs(filePath string) ([]*WeaknessType, error) {
	file, err := os.Open(filePath)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	byteValue, err := io.ReadAll(file)

	if err != nil {
		return nil, err
	}

	var cweList WeaknessCatalog

	err = xml.Unmarshal(byteValue, &cweList)

	if err != nil {
		return nil, err
	}

	return cweList.Weaknesses.Weakness, nil
}

func SyncCWEs(cweRepository CWERepository) {
	// read the CWEs from the local file system
	filePath := "cwec.xml"

	// parse the CWEs
	cwes, err := parseCWEs(filePath)

	if err != nil {
		panic(err)
	}

	models := make([]CWEModel, len(cwes))
	// insert the CWEs into the database
	for i, cwe := range cwes {
		models[i] = cwe.toModel()
	}

	err = cweRepository.SaveBatch(nil, models)

	if err != nil {
		panic(err)
	}
}
