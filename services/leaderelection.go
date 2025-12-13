package services

import (
	"log/slog"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/shared"
)

type leaderElectionConfig struct {
	LeaderID string `json:"leaderId"`
	LastPing int64  `json:"lastPing"`
}

type databaseLeaderElector struct {
	leaderElectorID string
	configService   shared.ConfigService
	isLeader        atomic.Bool // this variable gets updated by a daemon goroutine. Usage of atomic is required.
	daemonIsRunning bool
}

func NewDatabaseLeaderElector(configService shared.ConfigService) *databaseLeaderElector {
	leaderElector := databaseLeaderElector{
		configService: configService,
		// generate a random ID for this leader elector
		leaderElectorID: uuid.New().String(),
	}
	// start the daemon
	leaderElector.startDaemon()
	return &leaderElector
}

func randomNumberBetween(min, max int) int {
	return rand.Intn(max-min) + min // #nosec
}

func (e *databaseLeaderElector) daemon() {
	for {
		isLeader, err := e.checkIfLeader()
		if err != nil {
			slog.Error("could not check if leader", "err", err)
		}

		if isLeader {
			e.isLeader.Store(true)
		} else {
			e.isLeader.Store(false)
		}

		time.Sleep(time.Duration(randomNumberBetween(60, 359)) * time.Second)
	}
}

func (e *databaseLeaderElector) startDaemon() {
	e.daemonIsRunning = true
	go e.daemon()
}

func (e *databaseLeaderElector) IsLeader() bool {
	return e.isLeader.Load()
}

func (e *databaseLeaderElector) makeLeader() error {
	// there is no leader yet - overwrite it.
	return e.configService.SetJSONConfig("leaderElection", leaderElectionConfig{
		LeaderID: e.leaderElectorID,
		LastPing: time.Now().Unix(),
	})
}

func (e *databaseLeaderElector) checkIfLeader() (bool, error) {
	var config leaderElectionConfig

	err := e.configService.GetJSONConfig("leaderElection", &config)
	if err != nil {
		slog.Info("could not get leader election config", "err", err)
		// there is no leader yet - overwrite it.
		return true, e.makeLeader()
	}

	// check if the last ping was more than 360 seconds ago
	if time.Now().Unix()-config.LastPing > 360 {
		// probably the leader died - overwrite it.
		return true, e.makeLeader()
	}

	return config.LeaderID == e.leaderElectorID, nil
}
