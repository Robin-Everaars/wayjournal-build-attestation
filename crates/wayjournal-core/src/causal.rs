use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::RecordId;

pub trait CausalNode {
    fn record_id(&self) -> RecordId;
    fn parents(&self) -> &[RecordId];
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CausalError {
    #[error("causal graph exceeds the {maximum}-operation bound: {actual}")]
    TooManyOperations { maximum: usize, actual: usize },
    #[error("causal graph exceeds the {maximum}-edge bound: {actual}")]
    TooManyEdges { maximum: usize, actual: usize },
    #[error("causal parents must be strictly sorted and duplicate-free: {record_id}")]
    InvalidParents { record_id: RecordId },
    #[error("duplicate causal operation identity: {record_id}")]
    DuplicateRecordId { record_id: RecordId },
    #[error("record {record_id} has dangling parent {parent}")]
    DanglingParent {
        record_id: RecordId,
        parent: RecordId,
    },
    #[error("causal reachability exceeds the {maximum}-step fold bound")]
    ReachabilityBudget { maximum: usize },
    #[error("causal graph contains a cycle")]
    Cycle,
}

pub const MAX_CAUSAL_OPERATIONS: usize = 4096;
pub const MAX_CAUSAL_EDGES: usize = 65_536;
pub const MAX_REACHABILITY_STEPS: usize = 1_000_000;

pub struct CausalGraph<'a, T> {
    ordered: Vec<&'a T>,
    by_id: BTreeMap<RecordId, &'a T>,
}

impl<'a, T: CausalNode> CausalGraph<'a, T> {
    /// Builds a deterministic topological view over a complete local ancestry.
    ///
    /// # Errors
    /// Returns [`CausalError`] for duplicate identities, dangling parents, or cycles.
    pub fn new(nodes: &'a [T]) -> Result<Self, CausalError> {
        if nodes.len() > MAX_CAUSAL_OPERATIONS {
            return Err(CausalError::TooManyOperations {
                maximum: MAX_CAUSAL_OPERATIONS,
                actual: nodes.len(),
            });
        }
        let edges = nodes.iter().try_fold(0_usize, |total, node| {
            total.checked_add(node.parents().len())
        });
        if edges.is_none_or(|edges| edges > MAX_CAUSAL_EDGES) {
            return Err(CausalError::TooManyEdges {
                maximum: MAX_CAUSAL_EDGES,
                actual: edges.unwrap_or(usize::MAX),
            });
        }
        let mut by_id = BTreeMap::new();
        for node in nodes {
            if !node.parents().windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(CausalError::InvalidParents {
                    record_id: node.record_id(),
                });
            }
            if by_id.insert(node.record_id(), node).is_some() {
                return Err(CausalError::DuplicateRecordId {
                    record_id: node.record_id(),
                });
            }
        }
        for node in nodes {
            for parent in node.parents() {
                if !by_id.contains_key(parent) {
                    return Err(CausalError::DanglingParent {
                        record_id: node.record_id(),
                        parent: *parent,
                    });
                }
            }
        }

        let mut indegree = by_id
            .iter()
            .map(|(id, node)| (*id, node.parents().len()))
            .collect::<BTreeMap<_, _>>();
        let mut children = BTreeMap::<RecordId, Vec<RecordId>>::new();
        for node in nodes {
            for parent in node.parents() {
                children.entry(*parent).or_default().push(node.record_id());
            }
        }
        for values in children.values_mut() {
            values.sort_unstable();
        }
        let mut ready = indegree
            .iter()
            .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
            .collect::<BTreeSet<_>>();
        let mut ordered = Vec::with_capacity(nodes.len());
        while let Some(id) = ready.pop_first() {
            ordered.push(by_id[&id]);
            if let Some(values) = children.get(&id) {
                for child in values {
                    if let Some(degree) = indegree.get_mut(child) {
                        *degree -= 1;
                        if *degree == 0 {
                            ready.insert(*child);
                        }
                    }
                }
            }
        }
        if ordered.len() != nodes.len() {
            return Err(CausalError::Cycle);
        }

        Ok(Self { ordered, by_id })
    }

    #[must_use]
    pub fn ordered(&self) -> &[&'a T] {
        &self.ordered
    }

    #[must_use]
    pub fn observes(&self, observer: RecordId, candidate: RecordId) -> bool {
        let mut budget = MAX_REACHABILITY_STEPS;
        let mut exceeded = false;
        self.observes_bounded(observer, candidate, &mut budget, &mut exceeded)
    }

    pub(crate) fn observes_bounded(
        &self,
        observer: RecordId,
        candidate: RecordId,
        budget: &mut usize,
        exceeded: &mut bool,
    ) -> bool {
        let mut pending = self
            .by_id
            .get(&observer)
            .map_or_else(Vec::new, |node| node.parents().to_vec());
        let mut visited = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if *budget == 0 {
                *exceeded = true;
                return false;
            }
            *budget -= 1;
            if current == candidate {
                return true;
            }
            if visited.insert(current)
                && let Some(node) = self.by_id.get(&current)
            {
                pending.extend_from_slice(node.parents());
            }
        }
        false
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[derive(Clone)]
    struct Node {
        id: RecordId,
        parents: Vec<RecordId>,
    }
    impl CausalNode for Node {
        fn record_id(&self) -> RecordId {
            self.id
        }
        fn parents(&self) -> &[RecordId] {
            &self.parents
        }
    }
    fn id(value: usize) -> RecordId {
        format!("01913f1d-8e2a-7c30-8f4a-{value:012}")
            .parse()
            .unwrap()
    }

    #[test]
    fn maximum_valid_chain_and_exact_reachability_budget_are_accepted() {
        let nodes = (0..MAX_CAUSAL_OPERATIONS)
            .map(|index| Node {
                id: id(index),
                parents: (index > 0).then(|| id(index - 1)).into_iter().collect(),
            })
            .collect::<Vec<_>>();
        let graph = CausalGraph::new(&nodes).unwrap();
        let mut budget = MAX_CAUSAL_OPERATIONS - 1;
        let mut exceeded = false;
        assert!(graph.observes_bounded(
            id(MAX_CAUSAL_OPERATIONS - 1),
            id(0),
            &mut budget,
            &mut exceeded
        ));
        assert_eq!(budget, 0);
        assert!(!exceeded);
        assert!(!graph.observes_bounded(
            id(MAX_CAUSAL_OPERATIONS - 1),
            id(MAX_CAUSAL_OPERATIONS),
            &mut budget,
            &mut exceeded
        ));
        assert!(exceeded);
    }

    #[test]
    fn cumulative_exact_million_step_budget_accepts_then_rejects_next_step() {
        let parent = Node {
            id: id(0),
            parents: Vec::new(),
        };
        let child = Node {
            id: id(1),
            parents: vec![id(0)],
        };
        let nodes = [parent, child];
        let graph = CausalGraph::new(&nodes).unwrap();
        let mut budget = MAX_REACHABILITY_STEPS;
        let mut exceeded = false;
        for _ in 0..MAX_REACHABILITY_STEPS {
            assert!(graph.observes_bounded(id(1), id(0), &mut budget, &mut exceeded));
        }
        assert_eq!(budget, 0);
        assert!(!exceeded);
        assert!(!graph.observes_bounded(id(1), id(0), &mut budget, &mut exceeded));
        assert!(exceeded);
    }

    fn nodes_with_edges(edge_count: usize) -> Vec<Node> {
        let mut remaining = edge_count;
        (0..MAX_CAUSAL_OPERATIONS)
            .map(|index| {
                let count = remaining.min(index);
                remaining -= count;
                Node {
                    id: id(index),
                    parents: (0..count).map(id).collect(),
                }
            })
            .collect()
    }

    #[test]
    fn maximum_valid_edges_accept_and_edge_plus_one_rejects() {
        CausalGraph::new(&nodes_with_edges(MAX_CAUSAL_EDGES)).unwrap();
        assert!(matches!(
            CausalGraph::new(&nodes_with_edges(MAX_CAUSAL_EDGES + 1)),
            Err(CausalError::TooManyEdges { .. })
        ));
    }

    #[test]
    fn maximum_valid_fanout_and_parent_fan_in_are_accepted() {
        let fanout = (0..MAX_CAUSAL_OPERATIONS)
            .map(|index| Node {
                id: id(index),
                parents: (index > 0).then(|| id(0)).into_iter().collect(),
            })
            .collect::<Vec<_>>();
        CausalGraph::new(&fanout).unwrap();
        let many_parents = (0..MAX_CAUSAL_OPERATIONS)
            .map(|index| Node {
                id: id(index),
                parents: if index == MAX_CAUSAL_OPERATIONS - 1 {
                    (0..index).map(id).collect()
                } else {
                    Vec::new()
                },
            })
            .collect::<Vec<_>>();
        CausalGraph::new(&many_parents).unwrap();
    }
}
