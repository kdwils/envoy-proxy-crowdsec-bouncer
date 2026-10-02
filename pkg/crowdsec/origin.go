package crowdsec

import "github.com/crowdsecurity/crowdsec/pkg/models"

const defaultDecisionOrigin = "crowdsec"

// DecisionOrigin returns the metrics origin for a CrowdSec decision.
// It mirrors the origin normalization performed by the bouncer: if the origin
// is "lists", it returns "lists:<scenario>".
func DecisionOrigin(decision *models.Decision) string {
	if decision == nil {
		return defaultDecisionOrigin
	}
	origin := defaultDecisionOrigin
	if decision.Origin != nil && *decision.Origin != "" {
		origin = *decision.Origin
	}
	if origin == "lists" && decision.Scenario != nil && *decision.Scenario != "" {
		return "lists:" + *decision.Scenario
	}
	return origin
}
