package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// extract integrationID, projectID and issue Number from a ticketID or returns an error if invalid
func ExtractInformationFromTicketID(ticketID string) (string, int, int, error) {
	var integrationID string
	var projectID, issueNumber int

	indexColon := strings.Index(ticketID, ":")
	if indexColon == -1 {
		return integrationID, projectID, issueNumber, fmt.Errorf("invalid ticketID")
	}
	integrationID = ticketID[:indexColon-1]

	indexSlash := strings.Index(ticketID, "/")
	if indexSlash == -1 {
		return integrationID, projectID, issueNumber, fmt.Errorf("invalid ticketID")
	}
	projectID, err := strconv.Atoi(ticketID[indexColon+1 : indexSlash-1])
	if err != nil {
		return integrationID, projectID, issueNumber, err
	}

	issueNumber, err = strconv.Atoi(ticketID[indexSlash+1:])
	if err != nil {
		return integrationID, projectID, issueNumber, err
	}

	return integrationID, projectID, issueNumber, nil
}
