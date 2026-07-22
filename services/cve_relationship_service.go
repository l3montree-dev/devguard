package services

import (
	"context"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
)

type CVERelationshipService struct {
	cveRelationshipRepository shared.CVERelationshipRepository
}

func NewCVERelationshipService(cveRelationshipRepository shared.CVERelationshipRepository) *CVERelationshipService {
	return &CVERelationshipService{
		cveRelationshipRepository: cveRelationshipRepository,
	}
}

/*
Create a map where each CVE points to its alias.
Using empty structs to validate existence without using up too much space

	CVE1: {
		CVE2: struct{}
		CVE3: struct{}
		CVE4: struct{}
	}
*/
func (s *CVERelationshipService) CreateAliasRelationshipMapBatch(ctx context.Context, tx shared.DB, cveIDs []string) (map[string]map[string]struct{}, error) {
	cveRelationships, err := s.cveRelationshipRepository.FindCrossRelationshipsBatch(ctx, tx, cveIDs)
	if err != nil {
		return nil, err
	}

	cveAliasMap := make(map[string]map[string]struct{})

	for _, rel := range cveRelationships {
		if rel.RelationshipType != dtos.RelationshipTypeAlias {
			continue
		}

		if cveAliasMap[rel.SourceCVE] == nil {
			cveAliasMap[rel.SourceCVE] = make(map[string]struct{})
		}
		if cveAliasMap[rel.TargetCVE] == nil {
			cveAliasMap[rel.TargetCVE] = make(map[string]struct{})
		}

		for alias := range cveAliasMap[rel.SourceCVE] {
			cveAliasMap[alias][rel.TargetCVE] = struct{}{}
			cveAliasMap[rel.TargetCVE][alias] = struct{}{}
		}

		cveAliasMap[rel.SourceCVE][rel.TargetCVE] = struct{}{}
		cveAliasMap[rel.TargetCVE][rel.SourceCVE] = struct{}{}
	}

	return cveAliasMap, nil
}

func (s *CVERelationshipService) IsAlias(cveSource, cveTarget string, cveMap map[string]map[string]struct{}) bool {
	_, ok := cveMap[cveSource][cveTarget]
	return ok
}
