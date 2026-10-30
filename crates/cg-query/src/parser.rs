use crate::ast::*;
use crate::error::Result;

pub fn parse_query(input: &str) -> Result<Query> {
    let mut parser = Parser::new(input);
    parser.parse()
}

struct Parser<'a> {
    input: &'a str,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input }
    }

    fn parse(&mut self) -> Result<Query> {
        let mut source = None;
        let mut filters = Vec::new();
        let mut transforms = Vec::new();
        let mut limit = None;

        let parts = split_pipeline_pipes(self.input);

        // 1. Initial filter section (before first pipe)
        let initial_part = parts[0].trim();
        if !initial_part.is_empty() {
            let tokens = initial_part.split_whitespace();
            for token in tokens {
                if let Some((k, v)) = token.split_once('=') {
                    let k = k.trim();
                    let v = v.trim().trim_matches('"').trim_matches('\'');
                    if k == "source" || k == "index" {
                        source = Some(Source {
                            index_name: v.to_string(),
                            source_type: None,
                        });
                    } else if k == "sourcetype" || k == "source_type" {
                        if let Some(ref mut src) = source {
                            src.source_type = Some(v.to_string());
                        } else {
                            source = Some(Source {
                                index_name: "main".into(),
                                source_type: Some(v.to_string()),
                            });
                        }
                    } else {
                        filters.push(Filter::Comparison {
                            field: k.to_string(),
                            op: ComparisonOp::Eq,
                            value: Value::String(v.to_string()),
                        });
                    }
                }
            }
        }

        // 2. Transform pipeline (after each pipe)
        for part in &parts[1..] {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }

            let mut words = p.split_whitespace();
            let command = words.next().unwrap_or_default().to_lowercase();
            let remainder = p[command.len()..].trim();

            match command.as_str() {
                "head" => {
                    if let Ok(n) = remainder.parse::<usize>() {
                        limit = Some(n);
                        transforms.push(Transform::Head(n));
                    }
                }
                "tail" => {
                    if let Ok(n) = remainder.parse::<usize>() {
                        transforms.push(Transform::Tail(n));
                    }
                }
                "fields" => {
                    let fields: Vec<String> = remainder
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    transforms.push(Transform::Fields(fields));
                }
                "table" => {
                    let fields: Vec<String> = remainder
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    transforms.push(Transform::Table(fields));
                }
                "dedup" => {
                    let fields: Vec<String> = remainder
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    transforms.push(Transform::Dedup(fields));
                }
                "sort" => {
                    let mut sort_fields = Vec::new();
                    for token in remainder.split(',') {
                        let token = token.trim();
                        if let Some(stripped) = token.strip_prefix('-') {
                            sort_fields.push(SortField {
                                name: stripped.trim().to_string(),
                                ascending: false,
                            });
                        } else if let Some(stripped) = token.strip_prefix('+') {
                            sort_fields.push(SortField {
                                name: stripped.trim().to_string(),
                                ascending: true,
                            });
                        } else {
                            sort_fields.push(SortField {
                                name: token.to_string(),
                                ascending: true,
                            });
                        }
                    }
                    transforms.push(Transform::Sort(SortTransform {
                        fields: sort_fields,
                    }));
                }
                "stats" => {
                    let mut group_by = Vec::new();
                    let (aggs_part, by_part) = match remainder.split_once(" by ") {
                        Some((a, b)) => (a, Some(b)),
                        None => (remainder, None),
                    };

                    if let Some(by) = by_part {
                        group_by = by.split(',').map(|s| s.trim().to_string()).collect();
                    }

                    let mut aggregations = Vec::new();
                    for agg_token in aggs_part.split(',') {
                        let token = agg_token.trim();
                        if token.eq_ignore_ascii_case("count") {
                            aggregations.push(Aggregation {
                                function: AggFunction::Count,
                                field: String::new(),
                                alias: None,
                            });
                        } else if let Some((func, field_alias)) = token.split_once('(') {
                            let func_name = func.trim().to_lowercase();
                            let field_alias = field_alias.trim_end_matches(')').trim();
                            let (field, alias) = match field_alias.split_once(" as ") {
                                Some((f, a)) => (f.trim().to_string(), Some(a.trim().to_string())),
                                None => (field_alias.to_string(), None),
                            };

                            let agg_func = match func_name.as_str() {
                                "sum" => AggFunction::Sum,
                                "avg" => AggFunction::Avg,
                                "min" => AggFunction::Min,
                                "max" => AggFunction::Max,
                                "dc" => AggFunction::Dc,
                                _ => AggFunction::Count,
                            };

                            aggregations.push(Aggregation {
                                function: agg_func,
                                field,
                                alias,
                            });
                        }
                    }

                    transforms.push(Transform::Stats(StatsTransform {
                        aggregations,
                        group_by,
                    }));
                }
                "rename" => {
                    let mut pairs = Vec::new();
                    for token in remainder.split(',') {
                        if let Some((old, new)) = token.split_once(" as ") {
                            pairs.push((old.trim().to_string(), new.trim().to_string()));
                        } else if let Some((old, new)) = token.split_once(" AS ") {
                            pairs.push((old.trim().to_string(), new.trim().to_string()));
                        }
                    }
                    if !pairs.is_empty() {
                        transforms.push(Transform::Rename(pairs));
                    }
                }
                "eval" => {
                    if let Some((field, expr)) = remainder.split_once('=') {
                        transforms.push(Transform::Eval {
                            field: field.trim().to_string(),
                            expression: expr.trim().to_string(),
                        });
                    }
                }
                "where" => {
                    if let Some(filter) = parse_where_filter(remainder) {
                        transforms.push(Transform::Where(filter));
                    }
                }
                _ => {}
            }
        }

        Ok(Query {
            source,
            filters,
            transforms,
            limit,
            time_range: None,
        })
    }
}

fn split_pipeline_pipes(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut start = 0;
    let bytes = input.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\'' && !in_double {
            in_single = !in_single;
        } else if b == b'"' && !in_single {
            in_double = !in_double;
        } else if b == b'|' && !in_single && !in_double {
            parts.push(&input[start..i]);
            start = i + 1;
        }
    }
    if start <= input.len() {
        parts.push(&input[start..]);
    }
    parts
}

fn parse_where_filter(expr: &str) -> Option<Filter> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }

    // Check OR first (lower precedence)
    if let Some((left, right)) = expr.split_once(" OR ").or_else(|| expr.split_once(" or ")) {
        let l = parse_where_filter(left)?;
        let r = parse_where_filter(right)?;
        return Some(Filter::Or(Box::new(l), Box::new(r)));
    }

    // Check AND next
    if let Some((left, right)) = expr
        .split_once(" AND ")
        .or_else(|| expr.split_once(" and "))
    {
        let l = parse_where_filter(left)?;
        let r = parse_where_filter(right)?;
        return Some(Filter::And(Box::new(l), Box::new(r)));
    }

    // Single comparison
    if let Some((k, v)) = expr.split_once(">=") {
        Some(Filter::Comparison {
            field: k.trim().to_string(),
            op: ComparisonOp::Gte,
            value: parse_filter_val(v),
        })
    } else if let Some((k, v)) = expr.split_once("<=") {
        Some(Filter::Comparison {
            field: k.trim().to_string(),
            op: ComparisonOp::Lte,
            value: parse_filter_val(v),
        })
    } else if let Some((k, v)) = expr.split_once("!=") {
        Some(Filter::Comparison {
            field: k.trim().to_string(),
            op: ComparisonOp::Neq,
            value: parse_filter_val(v),
        })
    } else if let Some((k, v)) = expr.split_once('>') {
        Some(Filter::Comparison {
            field: k.trim().to_string(),
            op: ComparisonOp::Gt,
            value: parse_filter_val(v),
        })
    } else if let Some((k, v)) = expr.split_once('<') {
        Some(Filter::Comparison {
            field: k.trim().to_string(),
            op: ComparisonOp::Lt,
            value: parse_filter_val(v),
        })
    } else if let Some((k, v)) = expr.split_once('=') {
        Some(Filter::Comparison {
            field: k.trim().to_string(),
            op: ComparisonOp::Eq,
            value: parse_filter_val(v),
        })
    } else {
        None
    }
}

fn parse_filter_val(v: &str) -> Value {
    let clean = v.trim().trim_matches('"').trim_matches('\'');
    if let Ok(i) = clean.parse::<i64>() {
        Value::Integer(i)
    } else if let Ok(f) = clean.parse::<f64>() {
        Value::Float(f)
    } else if let Ok(b) = clean.parse::<bool>() {
        Value::Boolean(b)
    } else {
        Value::String(clean.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spl_style_query() {
        let q =
            r#"source="firewall" action=blocked | stats count by src_ip | sort -count | head 50"#;
        let query = parse_query(q).expect("Failed to parse query");

        assert_eq!(query.source.unwrap().index_name, "firewall");
        assert_eq!(query.filters.len(), 1);
        assert_eq!(query.transforms.len(), 3);
        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn test_parse_table_and_where() {
        let q = r#"index="endpoint" | where severity > 3 | table _time, host, user"#;
        let query = parse_query(q).expect("Failed to parse query");

        assert_eq!(query.source.unwrap().index_name, "endpoint");
        assert_eq!(query.transforms.len(), 2);
    }

    #[test]
    fn test_quoted_pipes_not_split() {
        let q = r#"source="syslog" msg="Pipe|Separated|Value" | head 10"#;
        let query = parse_query(q).expect("Failed to parse quoted pipes query");
        assert_eq!(query.transforms.len(), 1);
        assert_eq!(query.limit, Some(10));
    }

    #[test]
    fn test_compound_where_clause() {
        let q = r#"index="main" | where severity >= 4 AND action = "blocked""#;
        let query = parse_query(q).expect("Failed to parse compound where");
        assert_eq!(query.transforms.len(), 1);
        if let Transform::Where(Filter::And(left, right)) = &query.transforms[0] {
            if let Filter::Comparison { field, op, .. } = &**left {
                assert_eq!(field, "severity");
                assert_eq!(*op, ComparisonOp::Gte);
            } else {
                panic!("Expected Comparison on left");
            }
            if let Filter::Comparison { field, op, .. } = &**right {
                assert_eq!(field, "action");
                assert_eq!(*op, ComparisonOp::Eq);
            } else {
                panic!("Expected Comparison on right");
            }
        } else {
            panic!("Expected Where(Filter::And)");
        }
    }
}
