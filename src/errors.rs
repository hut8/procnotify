use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcNotifyError {
    #[error("No process selection criteria provided. Use either --name or --pid to specify a process to monitor.")]
    NullSelection,

    #[error("Cannot specify both --name and --pid. Use only one to identify the process to monitor.")]
    BothNameAndPid,

    #[error("No such process: {0}")]
    NoSuchProcess(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("RuntimeError: {0}")]
    RuntimeError(String),
}
