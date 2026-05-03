//! Unified dependency graph using petgraph
//!
//! Provides a petgraph-backed directed graph that represents resolved dependency
//! trees from any ecosystem lockfile. Nodes carry full package metadata (name,
//! version, ecosystem); edges carry version constraints and transitivity flags.

use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use std::collections::{HashMap, HashSet};

use tracing;

use crate::domain::dependency_graph::{DependencyGraph, PackageId, PackageMetadata, PackageNode};
use crate::domain::version_constraint::VersionConstraint;
use crate::domain::vulnerability::entities::Package;
use crate::domain::vulnerability::value_objects::{Ecosystem, Version};

/// Node weight in the unified dependency graph.
///
/// Carries the full package identity and metadata so that path analysis
/// and remediation queries never need a secondary lookup.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: PackageId,
    pub name: String,
    pub version: Version,
    pub ecosystem: Ecosystem,
    pub metadata: PackageMetadata,
}

impl GraphNode {
    pub fn from_package(id: PackageId, pkg: &Package, meta: PackageMetadata) -> Self {
        Self {
            id,
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            ecosystem: pkg.ecosystem.clone(),
            metadata: meta,
        }
    }
}

/// Edge weight in the unified dependency graph.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    pub constraint: VersionConstraint,
    pub is_transitive: bool,
    pub dep_type: Option<String>,
}

impl GraphEdge {
    /// Create an edge with default constraint and non-transitive.
    pub fn new(constraint: VersionConstraint) -> Self {
        Self {
            constraint,
            is_transitive: false,
            dep_type: None,
        }
    }
}

impl Default for GraphEdge {
    fn default() -> Self {
        Self {
            constraint: VersionConstraint::Any,
            is_transitive: false,
            dep_type: None,
        }
    }
}

/// A petgraph-backed dependency graph that provides fast path queries,
/// node-index lookups by `PackageId`, and root tracking.
#[derive(Debug, Clone)]
pub struct UnifiedDependencyGraph {
    graph: DiGraph<GraphNode, GraphEdge>,
    index: HashMap<PackageId, NodeIndex>,
    roots: HashSet<PackageId>,
}

impl UnifiedDependencyGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            index: HashMap::new(),
            roots: HashSet::new(),
        }
    }

    /// Creates a graph from an existing petgraph `DiGraph`, rebuilding the index.
    pub fn from_petgraph(graph: DiGraph<GraphNode, GraphEdge>) -> Self {
        let index: HashMap<PackageId, NodeIndex> = graph
            .node_indices()
            .map(|i| (graph[i].id.clone(), i))
            .collect();
        Self {
            graph,
            index,
            roots: HashSet::new(),
        }
    }

    pub fn node_index(&self, id: &PackageId) -> Option<NodeIndex> {
        self.index.get(id).copied()
    }

    pub fn internal_graph(&self) -> &DiGraph<GraphNode, GraphEdge> {
        &self.graph
    }

    pub fn roots(&self) -> &HashSet<PackageId> {
        &self.roots
    }

    pub fn is_direct(&self, id: &PackageId) -> bool {
        self.roots.contains(id)
    }

    /// Add a node, returning its `NodeIndex`.
    pub fn add_node(&mut self, id: PackageId, node: GraphNode) -> NodeIndex {
        if let Some(&idx) = self.index.get(&id) {
            return idx;
        }
        let idx = self.graph.add_node(node);
        self.index.insert(id, idx);
        idx
    }

    /// Add a directed edge between two existing nodes.
    pub fn add_edge(
        &mut self,
        from: &PackageId,
        to: &PackageId,
        edge: GraphEdge,
    ) -> Option<EdgeIndex> {
        let from_idx = self.index.get(from)?;
        let to_idx = self.index.get(to)?;
        Some(self.graph.add_edge(*from_idx, *to_idx, edge))
    }

    /// Look up a node by `PackageId`.
    pub fn node(&self, id: &PackageId) -> Option<&GraphNode> {
        let idx = self.index.get(id)?;
        self.graph.node_weight(*idx)
    }

    /// Mutable access to a node by `PackageId`.
    pub fn node_mut(&mut self, id: &PackageId) -> Option<&mut GraphNode> {
        let idx = self.index.get(id)?;
        self.graph.node_weight_mut(*idx)
    }

    /// Number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Check if a path exists between two packages using BFS (early exit).
    pub fn has_path(&self, from: &PackageId, to: &PackageId) -> bool {
        use petgraph::visit::Bfs;
        let Some(from_idx) = self.node_index(from) else {
            return false;
        };
        let Some(to_idx) = self.node_index(to) else {
            return false;
        };
        if from_idx == to_idx {
            return true;
        }
        let mut bfs = Bfs::new(&self.graph, from_idx);
        while let Some(nx) = bfs.next(&self.graph) {
            if nx == to_idx {
                return true;
            }
        }
        false
    }

    /// Returns the `NodeIndex` values of all direct dependencies of the given package.
    pub fn direct_dependencies(&self, id: &PackageId) -> Vec<NodeIndex> {
        let Some(idx) = self.node_index(id) else {
            return Vec::new();
        };
        self.graph.neighbors(idx).collect()
    }

    /// Returns all transitive dependency `NodeIndex` values reachable from the given package (DFS).
    pub fn transitive_dependencies(&self, id: &PackageId) -> Vec<NodeIndex> {
        let Some(start) = self.node_index(id) else {
            return Vec::new();
        };
        use petgraph::visit::Dfs;
        let mut dfs = Dfs::new(&self.graph, start);
        let mut result = Vec::new();
        while let Some(nx) = dfs.next(&self.graph) {
            if nx != start {
                result.push(nx);
            }
        }
        result
    }

    /// Get the edge between two packages, if one exists.
    pub fn edge(&self, from: &PackageId, to: &PackageId) -> Option<&GraphEdge> {
        let from_idx = self.index.get(from)?;
        let to_idx = self.index.get(to)?;
        let edge_idx = self.graph.find_edge(*from_idx, *to_idx)?;
        self.graph.edge_weight(edge_idx)
    }

    /// Convert back to the domain `DependencyGraph`.
    pub fn to_dependency_graph(&self) -> DependencyGraph {
        let mut dg = DependencyGraph::new();
        for idx in self.graph.node_indices() {
            let gn = &self.graph[idx];
            let pkg = Package::new(gn.name.clone(), gn.version.clone(), gn.ecosystem.clone())
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        "Package::new() validation failed for {}: {}; using best-effort",
                        gn.id,
                        e
                    );
                    Package {
                        name: gn.name.clone(),
                        version: gn.version.clone(),
                        ecosystem: gn.ecosystem.clone(),
                    }
                });
            dg.nodes.insert(
                gn.id.clone(),
                PackageNode {
                    id: gn.id.clone(),
                    package: pkg,
                    direct_dependencies: self
                        .graph
                        .neighbors(idx)
                        .map(|n| self.graph[n].id.clone())
                        .collect(),
                    dependents: self
                        .graph
                        .neighbors_directed(idx, petgraph::Direction::Incoming)
                        .map(|n| self.graph[n].id.clone())
                        .collect(),
                    metadata: PackageMetadata {
                        resolved_version: Some(gn.version.clone()),
                        is_direct: self.is_direct(&gn.id),
                        is_dev: gn.metadata.is_dev,
                        is_optional: gn.metadata.is_optional,
                        source_location: gn.metadata.source_location.clone(),
                    },
                },
            );
        }
        for edge_idx in self.graph.edge_indices() {
            let (from, to) = self
                .graph
                .edge_endpoints(edge_idx)
                .expect("edge_idx from edge_indices is always valid");
            let ge = &self.graph[edge_idx];
            dg.edges
                .push(crate::domain::dependency_graph::DependencyEdge {
                    from: self.graph[from].id.clone(),
                    to: self.graph[to].id.clone(),
                    constraint: ge.constraint.clone(),
                    is_transitive: ge.is_transitive,
                    source_location: None,
                    dep_type: ge.dep_type.clone(),
                });
        }
        dg.root_packages = self.roots.iter().cloned().collect();
        dg
    }

    /// Builds a `UnifiedDependencyGraph` from the domain `DependencyGraph`.
    pub fn from_dependency_graph(dg: &DependencyGraph) -> Result<Self, String> {
        let mut graph = DiGraph::<GraphNode, GraphEdge>::new();
        let mut node_map: HashMap<PackageId, NodeIndex> = HashMap::new();

        for (id, node) in &dg.nodes {
            let gn = GraphNode::from_package(
                id.clone(),
                &node.package,
                PackageMetadata {
                    resolved_version: node.metadata.resolved_version.clone(),
                    is_direct: node.metadata.is_direct,
                    is_dev: node.metadata.is_dev,
                    is_optional: node.metadata.is_optional,
                    source_location: node.metadata.source_location.clone(),
                },
            );
            let idx = graph.add_node(gn);
            node_map.insert(id.clone(), idx);
            let pkg_id = PackageId::from_package(&node.package);
            if pkg_id != *id {
                node_map.entry(pkg_id).or_insert(idx);
            }
        }

        for edge in &dg.edges {
            if !node_map.contains_key(&edge.from) {
                let idx = graph.add_node(GraphNode {
                    id: edge.from.clone(),
                    name: edge.from.name.clone(),
                    version: Version::new(0, 0, 0),
                    ecosystem: Ecosystem::from_alias(&edge.from.ecosystem).unwrap_or_else(|e| {
                        tracing::warn!(
                            "Unknown ecosystem '{}' for package {}; defaulting to npm: {}",
                            edge.from.ecosystem,
                            edge.from.name,
                            e
                        );
                        Ecosystem::Npm
                    }),
                    metadata: PackageMetadata {
                        resolved_version: None,
                        is_direct: false,
                        is_dev: false,
                        is_optional: false,
                        source_location: None,
                    },
                });
                node_map.insert(edge.from.clone(), idx);
            }
            if !node_map.contains_key(&edge.to) {
                let idx = graph.add_node(GraphNode {
                    id: edge.to.clone(),
                    name: edge.to.name.clone(),
                    version: Version::new(0, 0, 0),
                    ecosystem: Ecosystem::from_alias(&edge.to.ecosystem).unwrap_or_else(|e| {
                        tracing::warn!(
                            "Unknown ecosystem '{}' for package {}; defaulting to npm: {}",
                            edge.to.ecosystem,
                            edge.to.name,
                            e
                        );
                        Ecosystem::Npm
                    }),
                    metadata: PackageMetadata {
                        resolved_version: None,
                        is_direct: false,
                        is_dev: false,
                        is_optional: false,
                        source_location: None,
                    },
                });
                node_map.insert(edge.to.clone(), idx);
            }
        }

        for edge in &dg.edges {
            let from = node_map
                .get(&edge.from)
                .ok_or_else(|| format!("node not found: {}", edge.from))?;
            let to = node_map
                .get(&edge.to)
                .ok_or_else(|| format!("node not found: {}", edge.to))?;
            graph.add_edge(
                *from,
                *to,
                GraphEdge {
                    constraint: edge.constraint.clone(),
                    is_transitive: edge.is_transitive,
                    dep_type: edge.dep_type.clone(),
                },
            );
        }

        let roots: HashSet<PackageId> = dg.root_packages.iter().cloned().collect();

        Ok(Self {
            graph,
            index: node_map,
            roots,
        })
    }
}

impl Default for UnifiedDependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::dependency_graph::PackageNode;
    use crate::domain::vulnerability::entities::Package;
    use crate::domain::vulnerability::value_objects::{Ecosystem, Version};

    fn make_pkg(name: &str, version: &str, eco: Ecosystem) -> Package {
        Package::new(name.to_string(), Version::parse(version).unwrap(), eco).unwrap()
    }

    fn make_node(
        name: &str,
        version: &str,
        eco: Ecosystem,
        is_direct: bool,
    ) -> (PackageId, PackageNode) {
        let pkg = make_pkg(name, version, eco.clone());
        let id = PackageId::from_package(&pkg);
        let node = PackageNode {
            id: id.clone(),
            package: pkg,
            direct_dependencies: Vec::new(),
            dependents: Vec::new(),
            metadata: PackageMetadata {
                resolved_version: Some(Version::parse(version).unwrap()),
                is_direct,
                is_dev: false,
                is_optional: false,
                source_location: None,
            },
        };
        (id, node)
    }

    #[test]
    fn test_from_dependency_graph_roundtrip() {
        let mut dg = DependencyGraph::new();
        let (root_id, root_node) = make_node("root", "1.0.0", Ecosystem::Npm, true);
        let (dep_id, dep_node) = make_node("dep-a", "2.0.0", Ecosystem::Npm, false);
        dg.add_node(root_node);
        dg.add_node(dep_node);
        dg.add_edge(crate::domain::dependency_graph::DependencyEdge {
            from: root_id.clone(),
            to: dep_id.clone(),
            constraint: VersionConstraint::parse("^2.0.0").unwrap(),
            is_transitive: false,
            source_location: None,
            dep_type: None,
        });
        dg.root_packages.push(root_id.clone());

        let ug = UnifiedDependencyGraph::from_dependency_graph(&dg).unwrap();
        assert_eq!(ug.node_count(), 2);
        assert_eq!(ug.edge_count(), 1);
        assert!(ug.is_direct(&root_id));
        assert!(!ug.is_direct(&dep_id));
        assert!(ug.has_path(&root_id, &dep_id));

        // Check edge metadata
        let edge = ug.edge(&root_id, &dep_id).unwrap();
        assert!(!edge.is_transitive);
        assert_eq!(edge.dep_type, None);

        // Check node metadata
        let n = ug.node(&root_id).unwrap();
        assert_eq!(n.name, "root");
        assert_eq!(n.version.to_string(), "1.0.0");
        assert_eq!(n.ecosystem, Ecosystem::Npm);

        // Round-trip back
        let dg2 = ug.to_dependency_graph();
        assert_eq!(dg2.package_count(), 2);
        assert_eq!(dg2.dependency_count(), 1);
    }

    #[test]
    fn test_direct_dependencies() {
        let mut dg = DependencyGraph::new();
        let (root_id, root_node) = make_node("root", "1.0.0", Ecosystem::Npm, true);
        let (a_id, a_node) = make_node("a", "1.0.0", Ecosystem::Npm, false);
        let (b_id, b_node) = make_node("b", "1.0.0", Ecosystem::Npm, false);
        dg.add_node(root_node);
        dg.add_node(a_node);
        dg.add_node(b_node);
        dg.add_edge(crate::domain::dependency_graph::DependencyEdge {
            from: root_id.clone(),
            to: a_id.clone(),
            constraint: VersionConstraint::Any,
            is_transitive: false,
            source_location: None,
            dep_type: None,
        });
        dg.add_edge(crate::domain::dependency_graph::DependencyEdge {
            from: root_id.clone(),
            to: b_id.clone(),
            constraint: VersionConstraint::Any,
            is_transitive: true,
            source_location: None,
            dep_type: None,
        });
        dg.root_packages.push(root_id.clone());

        let ug = UnifiedDependencyGraph::from_dependency_graph(&dg).unwrap();
        let deps = ug.direct_dependencies(&root_id);
        assert_eq!(deps.len(), 2);

        let trans = ug.transitive_dependencies(&root_id);
        assert_eq!(trans.len(), 2);
    }

    #[test]
    fn test_ecosystem_preserved() {
        let (id, node) = make_node("log4j", "2.14.0", Ecosystem::Maven, true);
        let mut dg = DependencyGraph::new();
        dg.add_node(node);
        dg.root_packages.push(id.clone());

        let ug = UnifiedDependencyGraph::from_dependency_graph(&dg).unwrap();
        let n = ug.node(&id).unwrap();
        assert_eq!(n.ecosystem, Ecosystem::Maven);
    }

    #[test]
    fn test_missing_node_returns_none() {
        let ug = UnifiedDependencyGraph::new();
        let id = PackageId::new("npm".into(), "missing".into());
        assert!(ug.node(&id).is_none());
        assert!(ug.node_index(&id).is_none());
        assert!(!ug.has_path(&id, &id));
    }

    #[test]
    fn test_add_node_and_edge() {
        let mut ug = UnifiedDependencyGraph::new();
        let id_a = PackageId::new("npm".into(), "a".into());
        let id_b = PackageId::new("npm".into(), "b".into());

        let pkg_a = make_pkg("a", "1.0.0", Ecosystem::Npm);
        let pkg_b = make_pkg("b", "2.0.0", Ecosystem::Npm);

        ug.add_node(
            id_a.clone(),
            GraphNode::from_package(id_a.clone(), &pkg_a, PackageMetadata::default()),
        );
        ug.add_node(
            id_b.clone(),
            GraphNode::from_package(id_b.clone(), &pkg_b, PackageMetadata::default()),
        );
        ug.add_edge(
            &id_a,
            &id_b,
            GraphEdge {
                constraint: VersionConstraint::parse("^2.0.0").unwrap(),
                is_transitive: true,
                dep_type: Some("runtime".into()),
            },
        );

        assert_eq!(ug.node_count(), 2);
        assert_eq!(ug.edge_count(), 1);
        let edge = ug.edge(&id_a, &id_b).unwrap();
        assert!(edge.is_transitive);
        assert_eq!(edge.dep_type.as_deref(), Some("runtime"));
    }
}
