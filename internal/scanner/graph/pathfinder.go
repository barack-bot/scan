package graph

import "sort"

// Path represents a sequence of node IDs from a source to a target
type Path struct {
	Nodes  []string // node IDs in traversal order
	Weight float64  // sum of edge weights along the path
}

// AttackPath is a Path annotated with human-readable context
type AttackPath struct {
	Path
	StartCapability string
	EndCVE          string
	Severity        string
}

// FindAllPaths returns every simple path (no repeated nodes) from
// any confirmed capability to any CVE node in the graph.
// Results are sorted by descending weight (highest risk first).
func FindAllPaths(g *Graph) []*AttackPath {
	var paths []*AttackPath

	for _, start := range g.Nodes() {
		if start.Kind != KindCapability {
			continue
		}
		for _, end := range g.Nodes() {
			if end.Kind != KindCVE {
				continue
			}
			found := dfs(g, start.ID, end.ID, []string{}, 0.0)
			for _, p := range found {
				paths = append(paths, &AttackPath{
					Path:            p,
					StartCapability: start.ID,
					EndCVE:          end.ID,
					Severity:        end.Severity,
				})
			}
		}
	}

	// Sort highest weight first
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Weight > paths[j].Weight
	})

	return paths
}

// ShortestPath returns the single highest-weight path from any
// capability to the given CVE, or nil if the CVE is unreachable.
func ShortestPath(g *Graph, cveID string) *AttackPath {
	all := FindAllPaths(g)
	for _, p := range all {
		if p.EndCVE == cveID {
			return p // already sorted by weight desc, so first is best
		}
	}
	return nil
}

// --- DFS ---

// dfs performs a depth-first search from current toward target,
// accumulating the path and weight. Returns all simple paths found.
func dfs(g *Graph, current, target string, visited []string, weight float64) []Path {
	// Cycle check
	for _, v := range visited {
		if v == current {
			return nil
		}
	}

	newVisited := append(append([]string{}, visited...), current)

	if current == target {
		return []Path{{Nodes: newVisited, Weight: weight}}
	}

	var results []Path
	for _, next := range g.Successors(current) {
		// Find edge weight
		edgeWeight := edgeWeightBetween(g, current, next)
		sub := dfs(g, next, target, newVisited, weight+edgeWeight)
		results = append(results, sub...)
	}
	return results
}

// edgeWeightBetween returns the weight of the edge from → to, or 0 if not found
func edgeWeightBetween(g *Graph, from, to string) float64 {
	for _, e := range g.Edges() {
		if e.From == from && e.To == to {
			return e.Weight
		}
	}
	return 0
}
