// Package graph models a directed attack graph where nodes are
// capabilities/preconditions and edges are CVE exploit steps.
// This enables automatic blast-radius calculation: given what the
// scanner has confirmed (e.g. "apache 2.4.49 detected"), the graph
// shows which CVEs are reachable and what capabilities they grant.
package graph

import "fmt"

// NodeKind distinguishes capabilities from CVE nodes
type NodeKind int

const (
	KindCapability NodeKind = iota // e.g. "network_access", "php_enabled"
	KindCVE                        // e.g. "CVE-2021-41773"
)

// Node is a vertex in the attack graph
type Node struct {
	ID       string // unique identifier (capability name or CVE ID)
	Kind     NodeKind
	Label    string // human-readable name
	Severity string // only meaningful for CVE nodes
}

// Edge represents a directed relationship: satisfying From enables To
type Edge struct {
	From   string  // source node ID
	To     string  // destination node ID
	Weight float64 // exploitability weight 0.0-1.0
}

// Graph is a directed attack graph
type Graph struct {
	nodes map[string]*Node
	edges []*Edge
	// adjacency: from -> list of to
	adj map[string][]string
	// reverse adjacency: to -> list of from (for precondition lookup)
	radj map[string][]string
}

// New creates an empty attack graph
func New() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make([]*Edge, 0),
		adj:   make(map[string][]string),
		radj:  make(map[string][]string),
	}
}

// AddNode adds a node, ignoring duplicates
func (g *Graph) AddNode(n *Node) {
	if _, exists := g.nodes[n.ID]; !exists {
		g.nodes[n.ID] = n
	}
}

// AddEdge adds a directed edge from → to
func (g *Graph) AddEdge(from, to string, weight float64) error {
	if _, ok := g.nodes[from]; !ok {
		return fmt.Errorf("source node %q not in graph", from)
	}
	if _, ok := g.nodes[to]; !ok {
		return fmt.Errorf("destination node %q not in graph", to)
	}
	g.edges = append(g.edges, &Edge{From: from, To: to, Weight: weight})
	g.adj[from] = append(g.adj[from], to)
	g.radj[to] = append(g.radj[to], from)
	return nil
}

// Node retrieves a node by ID, returning nil if not found
func (g *Graph) Node(id string) *Node {
	return g.nodes[id]
}

// Nodes returns all nodes in the graph
func (g *Graph) Nodes() []*Node {
	result := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		result = append(result, n)
	}
	return result
}

// Edges returns all edges in the graph
func (g *Graph) Edges() []*Edge {
	return g.edges
}

// Successors returns the IDs of nodes reachable in one step from id
func (g *Graph) Successors(id string) []string {
	return g.adj[id]
}

// Predecessors returns the IDs of nodes that lead to id in one step
func (g *Graph) Predecessors(id string) []string {
	return g.radj[id]
}

// HasNode returns true if the graph contains a node with the given ID
func (g *Graph) HasNode(id string) bool {
	_, ok := g.nodes[id]
	return ok
}

// Size returns the number of nodes and edges
func (g *Graph) Size() (nodes int, edges int) {
	return len(g.nodes), len(g.edges)
}
