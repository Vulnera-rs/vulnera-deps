//! Contamination path analysis
//!
//! Determines whether a vulnerable package is reachable from a root package
//! through the dependency graph, and enumerates all propagation paths.

use petgraph::algo::all_simple_paths;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Bfs;
use std::collections::{HashSet, VecDeque};

use crate::domain::dependency_graph::PackageId;
use crate::services::graph::{GraphEdge, GraphNode, UnifiedDependencyGraph};

/// Result of a full contamination path analysis.
#[derive(Debug, Clone)]
pub struct ContaminationResult {
    pub contaminated: bool,
    pub all_paths: Vec<Vec<PackageId>>,
    pub shortest_path_index: Option<usize>,
    pub path_count: usize,
    pub truncated: bool,
}

/// Analyzes dependency paths between root and vulnerable packages.
pub struct ContaminationPathAnalyzer;

impl ContaminationPathAnalyzer {
    /// Returns true if there exists any path from `root` to `vulnerable` in the
    /// dependency graph. Uses BFS for fast early-exit detection.
    pub fn is_contaminated(
        graph: &UnifiedDependencyGraph,
        root: &PackageId,
        vulnerable: &PackageId,
    ) -> bool {
        let internal = graph.internal_graph();
        let Some(root_idx) = graph.node_index(root) else {
            return false;
        };
        let Some(vuln_idx) = graph.node_index(vulnerable) else {
            return false;
        };
        if root_idx == vuln_idx {
            return true;
        }
        let mut bfs = Bfs::new(internal, root_idx);
        while let Some(nx) = bfs.next(internal) {
            if nx == vuln_idx {
                return true;
            }
        }
        false
    }

    /// Finds all simple paths from `from` to `to`, capped at 100 paths to
    /// prevent exponential blowup.
    pub fn find_all_paths(
        graph: &UnifiedDependencyGraph,
        from: &PackageId,
        to: &PackageId,
    ) -> Vec<Vec<PackageId>> {
        let internal = graph.internal_graph();
        let Some(from_idx) = graph.node_index(from) else {
            return Vec::new();
        };
        let Some(to_idx) = graph.node_index(to) else {
            return Vec::new();
        };

        all_simple_paths::<Vec<NodeIndex>, _, std::collections::hash_map::RandomState>(
            internal, from_idx, to_idx, 0, None,
        )
        .take(100)
        .map(|path| Self::resolve_path(internal, &path))
        .collect()
    }

    /// BFS-based shortest path. Returns `None` if no path exists. Not subject to
    /// the path-count cap since BFS finds the single shortest path efficiently.
    pub fn shortest_path(
        graph: &UnifiedDependencyGraph,
        from: &PackageId,
        to: &PackageId,
    ) -> Option<Vec<PackageId>> {
        let internal = graph.internal_graph();
        let from_idx = graph.node_index(from)?;
        let to_idx = graph.node_index(to)?;

        if from_idx == to_idx {
            return Some(vec![from.clone()]);
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(vec![from_idx]);
        visited.insert(from_idx);

        while let Some(path) = queue.pop_front() {
            let current = *path.last().expect("BFS path is non-empty");
            for neighbor in internal.neighbors(current) {
                if neighbor == to_idx {
                    let mut full_path = path;
                    full_path.push(neighbor);
                    return Some(Self::resolve_path(internal, &full_path));
                }
                if visited.insert(neighbor) {
                    let mut new_path = path.clone();
                    new_path.push(neighbor);
                    queue.push_back(new_path);
                }
            }
        }

        None
    }

    /// Full analysis: enumerates all paths and identifies the shortest one.
    ///
    /// A convenient wrapper that calls `find_all_paths` and derives
    /// `shortest_path_index` from the result set.
    pub fn analyze(
        graph: &UnifiedDependencyGraph,
        root: &PackageId,
        vulnerable: &PackageId,
    ) -> ContaminationResult {
        let all_paths = Self::find_all_paths(graph, root, vulnerable);
        let path_count = all_paths.len();
        let truncated = path_count == 100;
        let contaminated = !all_paths.is_empty();

        let shortest_path_index = Self::shortest_path(graph, root, vulnerable)
            .and_then(|sp| all_paths.iter().position(|p| *p == sp));

        ContaminationResult {
            contaminated,
            all_paths,
            shortest_path_index,
            path_count,
            truncated,
        }
    }

    fn resolve_path(
        internal: &DiGraph<GraphNode, GraphEdge>,
        path: &[NodeIndex],
    ) -> Vec<PackageId> {
        path.iter().map(|idx| internal[*idx].id.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::dependency_graph::{PackageId, PackageMetadata};
    use crate::domain::vulnerability::entities::Package;
    use crate::domain::vulnerability::value_objects::{Ecosystem, Version};

    fn make_package_id(name: &str) -> PackageId {
        PackageId::new("npm".to_string(), name.to_string())
    }

    fn make_graph_node(name: &str) -> GraphNode {
        let pkg = Package::new(
            name.to_string(),
            Version::parse("1.0.0").unwrap(),
            Ecosystem::Npm,
        )
        .unwrap();
        GraphNode::from_package(
            PackageId::from_package(&pkg),
            &pkg,
            PackageMetadata::default(),
        )
    }

    fn build_chain(names: &[&str]) -> UnifiedDependencyGraph {
        let mut g = DiGraph::<GraphNode, GraphEdge>::new();
        let indices: Vec<NodeIndex> = names
            .iter()
            .map(|n| g.add_node(make_graph_node(n)))
            .collect();
        for pair in indices.windows(2) {
            g.add_edge(pair[0], pair[1], GraphEdge::default());
        }
        UnifiedDependencyGraph::from_petgraph(g)
    }

    fn build_edges(edge_list: &[(&str, &str)]) -> UnifiedDependencyGraph {
        let mut nodes: Vec<&str> = edge_list.iter().flat_map(|(a, b)| [*a, *b]).collect();
        nodes.sort();
        nodes.dedup();

        let mut g = DiGraph::<GraphNode, GraphEdge>::new();
        let node_set: std::collections::HashMap<&str, NodeIndex> = nodes
            .iter()
            .map(|n| (*n, g.add_node(make_graph_node(n))))
            .collect();
        for (from, to) in edge_list {
            g.add_edge(node_set[from], node_set[to], GraphEdge::default());
        }
        UnifiedDependencyGraph::from_petgraph(g)
    }

    #[test]
    fn simple_chain_is_contaminated() {
        let graph = build_chain(&["root", "A", "vulnerable"]);
        assert!(ContaminationPathAnalyzer::is_contaminated(
            &graph,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        ));
    }

    #[test]
    fn simple_chain_finds_shortest_path() {
        let graph = build_chain(&["root", "A", "vulnerable"]);
        let path = ContaminationPathAnalyzer::shortest_path(
            &graph,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        );
        let path = path.expect("expected a path");
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], make_package_id("root"));
        assert_eq!(path[1], make_package_id("A"));
        assert_eq!(path[2], make_package_id("vulnerable"));
    }

    #[test]
    fn simple_chain_analyze() {
        let graph = build_chain(&["root", "A", "vulnerable"]);
        let result = ContaminationPathAnalyzer::analyze(
            &graph,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        );
        assert!(result.contaminated);
        assert_eq!(result.path_count, 1);
        assert!(!result.truncated);
        assert_eq!(result.shortest_path_index, Some(0));
        assert_eq!(result.all_paths[0].len(), 3);
    }

    #[test]
    fn no_path_disconnected() {
        let mut g = DiGraph::<GraphNode, GraphEdge>::new();
        let r_idx = g.add_node(make_graph_node("root"));
        let a_idx = g.add_node(make_graph_node("A"));
        g.add_edge(r_idx, a_idx, GraphEdge::default());
        g.add_node(make_graph_node("vulnerable"));
        let merged = UnifiedDependencyGraph::from_petgraph(g);

        assert!(!ContaminationPathAnalyzer::is_contaminated(
            &merged,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        ));
        assert!(
            ContaminationPathAnalyzer::shortest_path(
                &merged,
                &make_package_id("root"),
                &make_package_id("vulnerable"),
            )
            .is_none()
        );
        assert!(
            ContaminationPathAnalyzer::find_all_paths(
                &merged,
                &make_package_id("root"),
                &make_package_id("vulnerable"),
            )
            .is_empty()
        );
    }

    #[test]
    fn diamond_dependency_two_paths() {
        let graph = build_edges(&[
            ("root", "A"),
            ("root", "B"),
            ("A", "vulnerable"),
            ("B", "vulnerable"),
        ]);
        let paths = ContaminationPathAnalyzer::find_all_paths(
            &graph,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        );
        assert_eq!(paths.len(), 2);
        for path in &paths {
            assert_eq!(path.first(), Some(&make_package_id("root")));
            assert_eq!(path.last(), Some(&make_package_id("vulnerable")));
        }
    }

    #[test]
    fn diamond_analyze_reports_both_paths() {
        let graph = build_edges(&[
            ("root", "A"),
            ("root", "B"),
            ("A", "vulnerable"),
            ("B", "vulnerable"),
        ]);
        let result = ContaminationPathAnalyzer::analyze(
            &graph,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        );
        assert!(result.contaminated);
        assert_eq!(result.path_count, 2);
        assert!(!result.truncated);
        assert!(result.shortest_path_index.is_some());
        for path in &result.all_paths {
            assert_eq!(path.len(), 3);
        }
    }

    #[test]
    fn is_contaminated_false_when_no_path() {
        let graph = build_chain(&["root", "A"]);
        assert!(!ContaminationPathAnalyzer::is_contaminated(
            &graph,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        ));
    }

    #[test]
    fn self_path_is_contaminated() {
        let graph = build_chain(&["root"]);
        assert!(ContaminationPathAnalyzer::is_contaminated(
            &graph,
            &make_package_id("root"),
            &make_package_id("root"),
        ));
        let sp = ContaminationPathAnalyzer::shortest_path(
            &graph,
            &make_package_id("root"),
            &make_package_id("root"),
        );
        assert_eq!(sp, Some(vec![make_package_id("root")]));
    }

    #[test]
    fn missing_nodes_return_empty() {
        let graph = build_chain(&["root", "A"]);
        assert!(
            ContaminationPathAnalyzer::find_all_paths(
                &graph,
                &make_package_id("nonexistent"),
                &make_package_id("A"),
            )
            .is_empty()
        );
        assert!(
            ContaminationPathAnalyzer::find_all_paths(
                &graph,
                &make_package_id("root"),
                &make_package_id("nonexistent"),
            )
            .is_empty()
        );
        assert!(!ContaminationPathAnalyzer::is_contaminated(
            &graph,
            &make_package_id("root"),
            &make_package_id("nonexistent"),
        ));
    }

    #[test]
    fn analyze_reports_truncated_when_over_100_paths() {
        let mut g = DiGraph::<GraphNode, GraphEdge>::new();
        let root = g.add_node(make_graph_node("root"));
        let vuln = g.add_node(make_graph_node("vulnerable"));
        // Add 101 distinct intermediate nodes, each creating a direct path
        for i in 0..101 {
            let mid = g.add_node(make_graph_node(&format!("mid_{}", i)));
            g.add_edge(root, mid, GraphEdge::default());
            g.add_edge(mid, vuln, GraphEdge::default());
        }
        let graph = UnifiedDependencyGraph::from_petgraph(g);
        let result = ContaminationPathAnalyzer::analyze(
            &graph,
            &make_package_id("root"),
            &make_package_id("vulnerable"),
        );
        assert_eq!(result.path_count, 100);
        assert!(result.truncated);
        assert!(result.contaminated);
    }
}
