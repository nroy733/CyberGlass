//! ThreatRank(TM) Algorithm: Dynamic Graph Centrality for Cyber Threats
//!
//! Inspired by Larry Page's PageRank, ThreatRank models organizational networks,
//! identities, credentials, processes, and vulnerabilities as a dynamic directed graph.
//! Rather than ranking documents by hyperlink prestige, ThreatRank models the random-walk
//! probability of an adversary traversing lateral movement vectors to compromise crown jewels.

use crate::entity::{Entity, EntityType};
use crate::graph::{Direction, KnowledgeGraph};
use crate::relationship::RelationType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

/// ThreatRank score and blast radius evaluation for a single entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRankResult {
    pub entity_id: Uuid,
    pub entity_type: EntityType,
    pub display_name: String,
    pub threat_rank: f64,      // 0.0 to 100.0 score
    pub base_criticality: f64, // Prior asset importance (0.0 to 1.0)
    pub incident_signal: f64,  // Direct compromise indicators
    pub blast_radius_reachable_nodes: usize,
    pub crown_jewels_at_risk: Vec<String>,
    pub is_critical_chokepoint: bool,
}

/// Organization-wide ThreatRank report across the entire knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRankReport {
    pub top_threats: Vec<ThreatRankResult>,
    pub total_entities_analyzed: usize,
    pub total_relationships_analyzed: usize,
    pub risk_index: f64, // 0.0 to 100.0 holistic risk
    pub critical_chokepoints: Vec<String>,
    pub execution_time_micros: u64,
}

/// Simulation of lateral movement progression from a patient-zero entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementSimulation {
    pub patient_zero_id: Uuid,
    pub patient_zero_name: String,
    pub simulated_hops: usize,
    pub compromised_entities: Vec<ThreatRankResult>,
    pub estimated_time_to_domain_admin_mins: u32,
    pub recommended_containment_chokepoints: Vec<String>,
}

pub struct ThreatRankEngine {
    damping_factor: f64,
    max_iterations: usize,
    convergence_threshold: f64,
}

impl Default for ThreatRankEngine {
    fn default() -> Self {
        Self {
            damping_factor: 0.85,
            max_iterations: 20,
            convergence_threshold: 1e-6,
        }
    }
}

impl ThreatRankEngine {
    pub fn new(damping_factor: f64, max_iterations: usize) -> Self {
        Self {
            damping_factor: damping_factor.clamp(0.1, 0.99),
            max_iterations,
            convergence_threshold: 1e-6,
        }
    }

    /// Evaluates base asset criticality prior C(u) based on entity type and naming convention.
    fn calculate_base_criticality(entity: &Entity) -> f64 {
        let name_lower = entity.display_name.to_lowercase();

        // 1. Crown jewels check (Domain Controller, IAM Vault, Database cluster, Prod API)
        if name_lower.contains("dc")
            || name_lower.contains("domain")
            || name_lower.contains("vault")
            || name_lower.contains("database")
            || name_lower.contains("prod-db")
            || name_lower.contains("ad-")
            || entity
                .tags
                .iter()
                .any(|t| t.to_lowercase() == "crown_jewel")
        {
            return 1.0;
        }

        // 2. High privilege identities
        if entity.entity_type == EntityType::User {
            if name_lower.contains("admin")
                || name_lower.contains("root")
                || name_lower.contains("svc_")
                || name_lower.contains("system")
            {
                return 0.95;
            }
            return 0.50;
        }

        // 3. Infrastructure & hosts
        if entity.entity_type == EntityType::Host {
            if name_lower.contains("prod") || name_lower.contains("gateway") {
                return 0.85;
            }
            return 0.40;
        }

        // 4. Vulnerabilities & Malware
        if entity.entity_type == EntityType::Vulnerability
            || entity.entity_type == EntityType::Malware
        {
            return 0.80;
        }

        0.25
    }

    /// Multiplier for edge relationship type representing lateral transfer probability.
    fn relation_transmission_weight(rel_type: &RelationType) -> f64 {
        match rel_type {
            RelationType::LateralMovement => 3.0,
            RelationType::EscalatedTo => 2.5,
            RelationType::Executed => 2.2,
            RelationType::Modified => 2.0,
            RelationType::AuthenticatedTo => 1.8,
            RelationType::ConnectedTo => 1.5,
            RelationType::CommunicatedWith => 1.4,
            RelationType::MemberOf => 1.6,
            RelationType::Spawned => 1.7,
            RelationType::Loaded => 1.3,
            RelationType::Downloaded => 1.5,
            _ => 1.0,
        }
    }

    /// Computes full ThreatRank report across the provided KnowledgeGraph.
    pub fn compute(&self, graph: &KnowledgeGraph) -> ThreatRankReport {
        let start = Instant::now();

        let entities = graph.search_entities("", None);
        let n = entities.len();

        if n == 0 {
            return ThreatRankReport {
                top_threats: Vec::new(),
                total_entities_analyzed: 0,
                total_relationships_analyzed: 0,
                risk_index: 0.0,
                critical_chokepoints: Vec::new(),
                execution_time_micros: start.elapsed().as_micros() as u64,
            };
        }

        let mut id_to_index = HashMap::with_capacity(n);
        let mut index_to_entity = Vec::with_capacity(n);
        let mut priors = Vec::with_capacity(n);

        let mut prior_sum = 0.0;
        for (idx, entity) in entities.into_iter().enumerate() {
            id_to_index.insert(entity.id, idx);
            let base_crit = Self::calculate_base_criticality(&entity);
            let incident_sig = (entity.risk_score / 100.0).clamp(0.0, 1.0);
            let prior = base_crit * 0.4 + incident_sig * 0.6;
            prior_sum += prior;
            priors.push((prior, base_crit, incident_sig));
            index_to_entity.push(entity);
        }

        // Normalize prior distribution
        if prior_sum <= 0.0 {
            prior_sum = 1.0;
        }
        let normalized_priors: Vec<f64> = priors.iter().map(|(p, _, _)| p / prior_sum).collect();

        // Build adjacency matrix / weighted outbound graph
        let mut outbound_adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
        let mut total_out_weight: Vec<f64> = vec![0.0; n];
        let mut rel_count = 0;

        for (u_idx, entity) in index_to_entity.iter().enumerate() {
            let rels = graph.get_relationships(&entity.id, Direction::Outbound);
            for rel in rels {
                if let Some(&v_idx) = id_to_index.get(&rel.target_entity_id) {
                    let w = rel.weight * Self::relation_transmission_weight(&rel.relation_type);
                    outbound_adj[u_idx].push((v_idx, w));
                    total_out_weight[u_idx] += w;
                    rel_count += 1;
                }
            }
        }

        // Initialize PageRank vector with priors
        let mut rank = normalized_priors.clone();
        let mut next_rank = vec![0.0; n];

        // Power iteration
        for _ in 0..self.max_iterations {
            let mut sink_rank_sum = 0.0;
            for i in 0..n {
                next_rank[i] = 0.0;
                if total_out_weight[i] == 0.0 {
                    sink_rank_sum += rank[i];
                }
            }

            for u in 0..n {
                let out_w = total_out_weight[u];
                if out_w > 0.0 {
                    let contrib = rank[u] / out_w;
                    for &(v, w) in &outbound_adj[u] {
                        next_rank[v] += contrib * w;
                    }
                }
            }

            // Distribute teleport and sink probabilities
            let mut diff = 0.0;
            for i in 0..n {
                let new_val = (1.0 - self.damping_factor) * normalized_priors[i]
                    + self.damping_factor * (next_rank[i] + sink_rank_sum * normalized_priors[i]);
                diff += (new_val - rank[i]).abs();
                rank[i] = new_val;
            }

            if diff < self.convergence_threshold {
                break;
            }
        }

        // Scale rank scores from 0.0 to 100.0 using logarithmic dynamic range
        let max_r = rank.iter().cloned().fold(0.0f64, f64::max);
        let min_r = rank.iter().cloned().fold(1.0f64, f64::min);
        let range = (max_r - min_r).max(1e-9);

        let mut results = Vec::with_capacity(n);
        let mut chokepoints = Vec::new();
        let mut total_threat_score = 0.0;

        for (i, entity) in index_to_entity.iter().enumerate() {
            let normalized = (rank[i] - min_r) / range;
            // Sigmoidal scaling to create clear separation between high and low threats
            let scaled_score = (1.0 / (1.0 + (-6.0 * (normalized - 0.4)).exp())) * 100.0;
            let final_score = (scaled_score * 0.7 + priors[i].2 * 100.0 * 0.3).clamp(1.0, 99.9);
            total_threat_score += final_score;

            // Compute blast radius within 3 hops
            let blast_radius = graph.traverse(&entity.id, 3);
            let mut reachable_crown_jewels = Vec::new();
            for (reach_ent, _) in &blast_radius {
                if Self::calculate_base_criticality(reach_ent) >= 0.85 {
                    reachable_crown_jewels.push(reach_ent.display_name.clone());
                }
            }
            reachable_crown_jewels.sort();
            reachable_crown_jewels.dedup();

            // Chokepoint check: High outbound degree with crown jewels reachable
            let is_chokepoint = outbound_adj[i].len() >= 2 && !reachable_crown_jewels.is_empty();
            if is_chokepoint && final_score > 60.0 {
                chokepoints.push(entity.display_name.clone());
            }

            results.push(ThreatRankResult {
                entity_id: entity.id,
                entity_type: entity.entity_type.clone(),
                display_name: entity.display_name.clone(),
                threat_rank: (final_score * 10.0).round() / 10.0,
                base_criticality: priors[i].1,
                incident_signal: priors[i].2,
                blast_radius_reachable_nodes: blast_radius.len(),
                crown_jewels_at_risk: reachable_crown_jewels,
                is_critical_chokepoint: is_chokepoint,
            });
        }

        // Sort descending by ThreatRank
        results.sort_by(|a, b| {
            b.threat_rank
                .partial_cmp(&a.threat_rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        chokepoints.sort();
        chokepoints.dedup();

        let avg_threat = total_threat_score / (n as f64);
        let risk_index = (avg_threat * 1.2).clamp(5.0, 95.0);

        ThreatRankReport {
            top_threats: results,
            total_entities_analyzed: n,
            total_relationships_analyzed: rel_count,
            risk_index: (risk_index * 10.0).round() / 10.0,
            critical_chokepoints: chokepoints,
            execution_time_micros: start.elapsed().as_micros() as u64,
        }
    }

    /// Simulates lateral movement from a specific breach point entity.
    pub fn simulate_lateral_movement(
        &self,
        graph: &KnowledgeGraph,
        patient_zero_id: &Uuid,
        max_hops: usize,
    ) -> Option<LateralMovementSimulation> {
        let root = graph.get_entity(patient_zero_id).ok()?;
        let report = self.compute(graph);
        let threat_map: HashMap<Uuid, &ThreatRankResult> = report
            .top_threats
            .iter()
            .map(|t| (t.entity_id, t))
            .collect();

        let traversal = graph.traverse(patient_zero_id, max_hops);
        let mut compromised = Vec::new();

        if let Some(root_tr) = threat_map.get(patient_zero_id) {
            compromised.push((*root_tr).clone());
        }

        for (ent, _) in traversal {
            if let Some(tr) = threat_map.get(&ent.id) {
                compromised.push((*tr).clone());
            }
        }

        let reach_crown_jewel = compromised.iter().any(|c| c.base_criticality >= 0.90);
        let estimated_mins = if reach_crown_jewel { 4 } else { 18 };

        let mut recommended_chokepoints = Vec::new();
        for c in &compromised {
            if c.is_critical_chokepoint {
                recommended_chokepoints.push(c.display_name.clone());
            }
        }
        if recommended_chokepoints.is_empty() && !compromised.is_empty() {
            recommended_chokepoints.push(root.display_name.clone());
        }

        Some(LateralMovementSimulation {
            patient_zero_id: *patient_zero_id,
            patient_zero_name: root.display_name,
            simulated_hops: max_hops,
            compromised_entities: compromised,
            estimated_time_to_domain_admin_mins: estimated_mins,
            recommended_containment_chokepoints: recommended_chokepoints,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityType};
    use crate::relationship::{RelationType, Relationship};

    #[test]
    fn test_threat_rank_convergence_and_prioritization() {
        let kg = KnowledgeGraph::new();

        // 1. Domain Controller (Crown Jewel)
        let dc = Entity::new(EntityType::Host, "AD-DC-01.corp.internal");
        let dc_id = kg.add_entity(dc).unwrap();

        // 2. Jumpbox / Gateway
        let jump = Entity::new(EntityType::Host, "jumpbox-gateway-01");
        let jump_id = kg.add_entity(jump).unwrap();

        // 3. Compromised Workstation
        let mut ws = Entity::new(EntityType::Host, "ws-dev-alice");
        ws.risk_score = 90.0; // High incident signal
        let ws_id = kg.add_entity(ws).unwrap();

        // 4. Isolated Workstation (Clean)
        let clean_ws = Entity::new(EntityType::Host, "ws-marketing-bob");
        let clean_ws_id = kg.add_entity(clean_ws).unwrap();

        // Edges: Compromised Workstation -> Jumpbox -> Domain Controller
        kg.add_relationship(Relationship::new(
            ws_id,
            jump_id,
            RelationType::LateralMovement,
        ))
        .unwrap();
        kg.add_relationship(Relationship::new(jump_id, dc_id, RelationType::EscalatedTo))
            .unwrap();

        let engine = ThreatRankEngine::default();
        let report = engine.compute(&kg);

        assert_eq!(report.total_entities_analyzed, 4);
        assert!(report.top_threats.len() == 4);
        assert!(
            report.execution_time_micros < 50_000,
            "Must execute in under 50ms"
        );

        // The compromised workstation and the jumpbox on the path to DC should have higher ThreatRank than clean_ws
        let ws_threat = report
            .top_threats
            .iter()
            .find(|t| t.entity_id == ws_id)
            .unwrap();
        let clean_threat = report
            .top_threats
            .iter()
            .find(|t| t.entity_id == clean_ws_id)
            .unwrap();
        assert!(
            ws_threat.threat_rank > clean_threat.threat_rank,
            "Compromised node with path to DC must have higher ThreatRank than clean node"
        );

        // Simulation test
        let sim = engine
            .simulate_lateral_movement(&kg, &ws_id, 3)
            .expect("Simulation succeeds");
        assert_eq!(sim.patient_zero_name, "ws-dev-alice");
        assert!(sim.compromised_entities.len() >= 3);
        assert_eq!(sim.estimated_time_to_domain_admin_mins, 4);
    }
}
