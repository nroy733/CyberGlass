use thiserror::Error;

#[derive(Error, Debug)]
pub enum DetectionError {
    #[error("Rule compilation error: {0}")]
    RuleCompile(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(String),

    #[error("Alert not found: {0}")]
    AlertNotFound(String),

    #[error("Invalid Sigma rule: {0}")]
    InvalidSigmaRule(String),

    #[error("Evaluation error: {0}")]
    EvaluationError(String),

    #[error("Correlation error: {0}")]
    CorrelationError(String),
}

pub type Result<T> = std::result::Result<T, DetectionError>;
