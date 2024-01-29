package flaw

import (
	"context"
	"log/slog"
	"time"

	"github.com/l3montree-dev/flawfix/internal/core/cwe"
)

type Enricher interface {
	AsyncEnrich(flaw []Model)
}

type enricher struct {
	cveService     cwe.CVEService
	flawRepository Repository
}

func NewEnricher(cveService cwe.CVEService, flawRepository Repository) Enricher {
	return &enricher{
		cveService:     cveService,
		flawRepository: flawRepository,
	}
}

func (e enricher) AsyncEnrich(flaw []Model) {
	for _, f := range flaw {
		go func(f Model) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// get the CVE
			cve, err := e.cveService.GetCVE(ctx, f.RuleID)

			if err != nil {
				slog.Info("could not get cve", "err", err)
			}

			if err == nil {
				f.CVE = &cve
				if err = e.flawRepository.Update(nil, &f); err != nil {
					slog.Info("could not update flaw", "err", err)
				}
			}
		}(f)
	}
}
