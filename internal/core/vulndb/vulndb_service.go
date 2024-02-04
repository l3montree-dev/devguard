package vulndb

import (
	"log/slog"
	"time"
)

type vulnDBService struct {
	leaderElector leaderElector

	mitreService mitreService
	epssService  epssService
	nvdService   NVDService
	osvService   osvService

	configService configService
}

func newVulnDBService(leaderElector leaderElector, mitreService mitreService, epssService epssService, nvdService NVDService, configService configService, osvService osvService) *vulnDBService {
	return &vulnDBService{
		leaderElector: leaderElector,

		osvService:   osvService,
		mitreService: mitreService,
		epssService:  epssService,
		nvdService:   nvdService,

		configService: configService,
	}
}

func (v *vulnDBService) mirror() {
	for {
		// first mirror mitre
		// then mirror nvd
		// then mirror epss
		// then sleep for 2 hours
		if v.leaderElector.IsLeader() {
			// check the last time we mirrored
			var lastMirror struct {
				Time time.Time `json:"time"`
			}
			v.configService.SetJSONConfig("vulndb.last_mirror", struct {
				Time time.Time `json:"time"`
			}{
				Time: time.Now(),
			})

			v.configService.GetJSONConfig("vulndb.last_mirror", &lastMirror)
			if time.Since(lastMirror.Time) < 2*time.Hour {
				slog.Info("last mirror was less than 2 hours ago. Starting mirror process")
				if err := v.mitreService.mirror(); err != nil {
					slog.Error("could not mirror mitre cwes", "err", err)
				} else {
					slog.Info("successfully mirrored mitre cwes")
				}
				if err := v.nvdService.mirror(); err != nil {
					slog.Error("could not mirror nvd", "err", err)
					panic(err)
				} else {
					slog.Info("successfully mirrored nvd")
				}
				if err := v.epssService.mirror(); err != nil {
					slog.Error("could not mirror epss", "err", err)
				} else {
					slog.Info("successfully mirrored epss")
				}
				if err := v.osvService.mirror(); err != nil {
					slog.Error("could not mirror osv", "err", err)
				}
			} else {
				slog.Info("last mirror was less than 2 hours ago. Not mirroring", "lastMirror", lastMirror.Time, "now", time.Now())
			}

		} else {
			// if we are not the leader, sleep for 5 minutes
			slog.Info("not the leader. Waiting for 5 minutes to check again")
			time.Sleep(5 * time.Minute)
		}
	}
}

func (v *vulnDBService) startMirrorDaemon() {

	//go v.mirror()
}
