use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcNotifyError {
    #[error("No process selection criteria provided")]
    NullSelection,

    #[error("No such process: {0}")]
    NoSuchProcess(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("RuntimeError error: {0}")]
    RuntimeError(String),
}
