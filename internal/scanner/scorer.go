package scanner

import (
	"ke-scan/internal/db"
	"strings"
)

// RiskAssessment holds calculated technical weightings for vulnerabilities
type RiskAssessment struct {
	BaseScore       int     // 0 - 100 base severity
	ConfidenceScore float64 // 0.0 - 1.0 architecture certainty
	AdjustedScore   int     // Final normalized risk matrix score
	IsSuspected     bool    // True if vulnerability is deduced via heuristic fallback
}

// AssessRisk evaluates finding impact accounting for configuration uncertainty
func AssessRisk(f *db.Finding, confidence float64) RiskAssessment {
	assessment := RiskAssessment{
		BaseScore:       10,
		ConfidenceScore: confidence,
		IsSuspected:     confidence < 0.90,
	}

	// Calculate base technical score
	switch strings.ToLower(f.Severity) {
	case "critical":
		assessment.BaseScore = 100
	case "high":
		assessment.BaseScore = 70
	case "medium":
		assessment.BaseScore = 40
	case "low":
		assessment.BaseScore = 20
	default:
		assessment.BaseScore = 10
	}

	// Calculate adjusted risk: BaseScore * Confidence Modifier
	// Ensures unverified, hidden server guesses do not result in false positives that wake engineers up at 3 AM.
	if assessment.IsSuspected {
		// Dampen score but apply a minimum baseline ceiling of 30 so critical vulnerabilities remain visible
		calc := float64(assessment.BaseScore) * confidence
		assessment.AdjustedScore = int(calc)
		if assessment.AdjustedScore < 30 && assessment.BaseScore >= 70 {
			assessment.AdjustedScore = 30
		}
	} else {
		assessment.AdjustedScore = assessment.BaseScore
	}

	return assessment
}

// ScoreFinding maintains backwards compatibility with legacy modules
func ScoreFinding(f *db.Finding) int {
	assessment := AssessRisk(f, 1.0)
	return assessment.AdjustedScore
}
