use crate::ast::*;

pub struct QueryOptimizer;

impl QueryOptimizer {
    pub fn optimize(mut query: Query) -> Query {
        // If query has a Head(n) transform, propagate it to query.limit
        for transform in &query.transforms {
            if let Transform::Head(n) = transform {
                query.limit = Some(query.limit.map_or(*n, |cur| cur.min(*n)));
            }
        }

        query
    }
}
