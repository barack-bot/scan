package graph

import (
	"strings"

	"ke-scan/internal/scanner/loader"
)

// Builder constructs an attack graph from a CVE loader and a set of
// confirmed capabilities (from fingerprinting + precondition checks).
type Builder struct {
	cves          *loader.Loader
	confirmedCaps map[string]bool // capabilities confirmed on the target
}

// NewBuilder creates a builder with the given CVE database
func NewBuilder(cves *loader.Loader) *Builder {
	return &Builder{
		cves:          cves,
		confirmedCaps: make(map[string]bool),
	}
}

// ConfirmCapability marks a capability as present on the target.
// e.g. "apache", "php", "network_access", "apache_2.4.49"
func (b *Builder) ConfirmCapability(cap string) {
	b.confirmedCaps[strings.ToLower(cap)] = true
}

// ConfirmCapabilities marks multiple capabilities at once
func (b *Builder) ConfirmCapabilities(caps []string) {
	for _, c := range caps {
		b.ConfirmCapability(c)
	}
}

// Build constructs and returns the attack graph for confirmed capabilities.
//
// Algorithm:
//  1. Add a node for every confirmed capability.
//  2. For each CVE in the database, check if ALL of its required
//     capabilities are confirmed.
//  3. If yes, add the CVE node and edges: capability → CVE for each
//     required cap, and CVE → granted_cap for each capability the CVE
//     would grant the attacker.
//  4. Repeat until no new CVEs are added (transitive expansion).
func (b *Builder) Build() *Graph {
	g := New()

	// Seed with confirmed capabilities
	activeCaps := make(map[string]bool)
	for cap := range b.confirmedCaps {
		activeCaps[cap] = true
		g.AddNode(&Node{
			ID:    cap,
			Kind:  KindCapability,
			Label: cap,
		})
	}

	// Iteratively expand: a CVE may grant new capabilities that
	// unlock further CVEs (attack chaining)
	changed := true
	for changed {
		changed = false
		for _, cve := range b.cves.GetAll() {
			if g.HasNode(cve.ID) {
				continue // already added
			}
			if b.allRequiredPresent(cve, activeCaps) {
				// Add the CVE node
				g.AddNode(&Node{
					ID:       cve.ID,
					Kind:     KindCVE,
					Label:    cve.Title,
					Severity: cve.Severity,
				})

				// Edges: each required software → CVE
				for _, req := range cve.AffectedSoftware {
					req = strings.ToLower(req)
					if activeCaps[req] {
						if !g.HasNode(req) {
							g.AddNode(&Node{ID: req, Kind: KindCapability, Label: req})
						}
						weight := cvssToWeight(cve.CVSSScore)
						_ = g.AddEdge(req, cve.ID, weight)
					}
				}

				// Edges: CVE → each granted capability (attack chaining)
				for _, grantedCap := range cve.Grants {
					grantedCap = strings.ToLower(grantedCap)
					if !g.HasNode(grantedCap) {
						g.AddNode(&Node{
							ID:    grantedCap,
							Kind:  KindCapability,
							Label: grantedCap,
						})
					}
					weight := cvssToWeight(cve.CVSSScore)
					_ = g.AddEdge(cve.ID, grantedCap, weight)

					// Mark this capability as active for transitive expansion
					if !activeCaps[grantedCap] {
						activeCaps[grantedCap] = true
						changed = true
					}
				}

				changed = true
			}
		}
	}

	return g
}

// ReachableCVEs returns the IDs of all CVE nodes in the graph,
// i.e. CVEs that are exploitable given confirmed capabilities.
func ReachableCVEs(g *Graph) []string {
	var ids []string
	for _, n := range g.Nodes() {
		if n.Kind == KindCVE {
			ids = append(ids, n.ID)
		}
	}
	return ids
}

// --- helpers ---

// allRequiredPresent checks whether every software name in AffectedSoftware
// has been confirmed as a capability on the target.
func (b *Builder) allRequiredPresent(cve *loader.CVE, activeCaps map[string]bool) bool {
	if len(cve.AffectedSoftware) == 0 {
		return false
	}
	for _, req := range cve.AffectedSoftware {
		if !activeCaps[strings.ToLower(req)] {
			return false
		}
	}
	return true
}

// cvssToWeight converts a CVSS score (0-10) to an edge weight (0-1)
func cvssToWeight(cvss float64) float64 {
	if cvss <= 0 {
		return 0.1
	}
	if cvss > 10 {
		return 1.0
	}
	return cvss / 10.0
}
