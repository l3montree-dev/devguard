package vulndb

import "net/http"

type debianSecurityTrackerService struct {
	httpClient *http.Client
}

func NewDebianSecurityTrackerService() debianSecurityTrackerService {
	return debianSecurityTrackerService{
		httpClient: &http.Client{},
	}
}

func (d debianSecurityTrackerService) Mirror() error {
	return nil
}
