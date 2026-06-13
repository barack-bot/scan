package graph

import "sort"

// BlastRadius describes the impact of a single CVE being exploited:
// which further CVEs become reachable, and what capabilities are gained.
type BlastRadius struct {
	RootCVE           string   // the CVE being analysed
	ReachableCVEs     []string // other CVEs unlocked by exploiting RootCVE
	GrantedCaps       []string // capabilities gained after exploiting RootCVE
	Depth             int      // maximum chain depth
	CriticalReachable int      // count of critical-severity CVEs reachable
}

// Analyse computes the blast radius for a given CVE node.
// It performs a BFS from the CVE node following outgoing edges,
// collecting all reachable CVE nodes and capability nodes.
func Analyse(g *Graph, cveID string) *BlastRadius {
	br := &BlastRadius{
		RootCVE: cveID,
	}

	if !g.HasNode(cveID) {
		return br
	}

	visited := make(map[string]bool)
	type item struct {
		id    string
		depth int
	}

	queue := []item{{id: cveID, depth: 0}}
	visited[cveID] = true

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if cur.depth > br.Depth {
			br.Depth = cur.depth
		}

		for _, next := range g.Successors(cur.id) {
			if visited[next] {
				continue
			}
			visited[next] = true

			node := g.Node(next)
			if node == nil {
				continue
			}

			switch node.Kind {
			case KindCVE:
				br.ReachableCVEs = append(br.ReachableCVEs, next)
				if node.Severity == "critical" {
					br.CriticalReachable++
				}
				queue = append(queue, item{id: next, depth: cur.depth + 1})
			case KindCapability:
				br.GrantedCaps = append(br.GrantedCaps, next)
				// Follow capability edges too so we count full chain depth
				queue = append(queue, item{id: next, depth: cur.depth + 1})
			}
		}
	}

	sort.Strings(br.ReachableCVEs)
	sort.Strings(br.GrantedCaps)
	return br
}

// AnalyseAll computes blast radius for every CVE node in the graph,
// sorted by number of reachable CVEs descending (highest impact first).
func AnalyseAll(g *Graph) []*BlastRadius {
	var results []*BlastRadius

	for _, n := range g.Nodes() {
		if n.Kind != KindCVE {
			continue
		}
		results = append(results, Analyse(g, n.ID))
	}

	sort.Slice(results, func(i, j int) bool {
		return len(results[i].ReachableCVEs) > len(results[j].ReachableCVEs)
	})

	return results
}
