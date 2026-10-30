use crate::entity::{Entity, EntityType};
use crate::error::{OntologyError, Result};
use crate::relationship::Relationship;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

pub struct KnowledgeGraph {
    entities: DashMap<Uuid, Entity>,
    lookup_index: DashMap<(EntityType, String), Uuid>,
    relationships: DashMap<Uuid, Relationship>,
    outbound: DashMap<Uuid, Vec<Uuid>>,
    inbound: DashMap<Uuid, Vec<Uuid>>,
}

impl Default for KnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self {
            entities: DashMap::new(),
            lookup_index: DashMap::new(),
            relationships: DashMap::new(),
            outbound: DashMap::new(),
            inbound: DashMap::new(),
        }
    }

    /// Add or merge an entity in O(1) time using the secondary lookup index.
    pub fn add_entity(&self, entity: Entity) -> Result<Uuid> {
        let lookup_key = (entity.entity_type.clone(), entity.display_name.clone());

        if let Some(id_ref) = self.lookup_index.get(&lookup_key) {
            let id = *id_ref.value();
            if let Some(mut existing) = self.entities.get_mut(&id) {
                existing.merge_with(&entity);
            }
            return Ok(id);
        }

        let id = entity.id;
        self.lookup_index.insert(lookup_key, id);
        self.entities.insert(id, entity);
        Ok(id)
    }

    pub fn get_entity(&self, id: &Uuid) -> Result<Entity> {
        self.entities
            .get(id)
            .map(|e| e.value().clone())
            .ok_or_else(|| OntologyError::EntityNotFound(id.to_string()))
    }

    pub fn search_entities(&self, query: &str, entity_type: Option<EntityType>) -> Vec<Entity> {
        let q = query.to_lowercase();
        self.entities
            .iter()
            .filter(|e| {
                let matches_type = entity_type.as_ref().map_or(true, |t| &e.entity_type == t);
                let matches_query = q.is_empty() || e.display_name.to_lowercase().contains(&q);
                matches_type && matches_query
            })
            .map(|e| e.value().clone())
            .collect()
    }

    pub fn get_all_relationships(&self) -> Vec<Relationship> {
        self.relationships
            .iter()
            .map(|r| r.value().clone())
            .collect()
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.entities.len(), self.relationships.len())
    }

    pub fn add_relationship(&self, rel: Relationship) -> Result<Uuid> {
        let id = rel.id;
        let src = rel.source_entity_id;
        let dst = rel.target_entity_id;

        self.relationships.insert(id, rel);

        self.outbound.entry(src).or_default().push(id);
        self.inbound.entry(dst).or_default().push(id);

        Ok(id)
    }

    pub fn get_relationships(&self, entity_id: &Uuid, direction: Direction) -> Vec<Relationship> {
        let mut rel_ids = Vec::new();

        if direction == Direction::Outbound || direction == Direction::Both {
            if let Some(out) = self.outbound.get(entity_id) {
                rel_ids.extend(out.value().iter().copied());
            }
        }

        if direction == Direction::Inbound || direction == Direction::Both {
            if let Some(inp) = self.inbound.get(entity_id) {
                rel_ids.extend(inp.value().iter().copied());
            }
        }

        rel_ids
            .into_iter()
            .filter_map(|rid| self.relationships.get(&rid).map(|r| r.value().clone()))
            .collect()
    }

    pub fn traverse(&self, start: &Uuid, max_depth: usize) -> Vec<(Entity, Vec<Relationship>)> {
        let mut results = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        if let Ok(_root) = self.get_entity(start) {
            visited.insert(*start);
            queue.push_back((*start, 0));

            while let Some((curr_id, depth)) = queue.pop_front() {
                if depth >= max_depth {
                    continue;
                }

                let rels = self.get_relationships(&curr_id, Direction::Outbound);
                for rel in &rels {
                    let next_id = rel.target_entity_id;
                    if !visited.contains(&next_id) {
                        visited.insert(next_id);
                        if let Ok(next_entity) = self.get_entity(&next_id) {
                            results.push((next_entity, vec![rel.clone()]));
                            queue.push_back((next_id, depth + 1));
                        }
                    }
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::EntityType;
    use crate::relationship::RelationType;

    #[test]
    fn test_knowledge_graph_traversal() {
        let kg = KnowledgeGraph::new();

        let host = Entity::new(EntityType::Host, "server-prod-01");
        let host_id = kg.add_entity(host).unwrap();

        let user = Entity::new(EntityType::User, "attacker_compromised");
        let user_id = kg.add_entity(user).unwrap();

        let ip = Entity::new(EntityType::IpAddress, "185.220.101.5");
        let ip_id = kg.add_entity(ip).unwrap();

        let rel1 = Relationship::new(user_id, host_id, RelationType::LateralMovement);
        kg.add_relationship(rel1).unwrap();

        let rel2 = Relationship::new(host_id, ip_id, RelationType::CommunicatedWith);
        kg.add_relationship(rel2).unwrap();

        let traversed = kg.traverse(&user_id, 3);
        assert_eq!(
            traversed.len(),
            2,
            "BFS traversal must trace 2 hops (User -> Host -> IP)"
        );
    }
}
