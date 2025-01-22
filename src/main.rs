use clap::Parser;
use errors::ProcNotifyError;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{Address, SmtpTransport};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::path::Path;
use sysinfo::{ProcessesToUpdate, System};

mod errors;

const FROM_ADDDRESS: &str = "process-notifier@hut8.tools";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the process to monitor
    #[arg(short, long)]
    name: Option<String>,

    /// Process ID to monitor
    #[arg(short, long)]
    pid: Option<i32>,

    /// Email address to notify
    #[arg(short, long)]
    email: String,

    /// SMTP Port
    #[arg(long, default_value = "587", env = "SMTP_PORT")]
    smtp_port: u16,

    /// SMTP Server
    #[arg(short, long, env = "SMTP_SERVER")]
    smtp_server: String,

    /// SMTP Username
    #[arg(short, long, env = "SMTP_USERNAME")]
    smtp_username: String,

    /// SMTP Password
    #[arg(short, long, env = "SMTP_PASSWORD")]
    smtp_password: String,
}

#[derive(Debug, Clone)]
pub struct ProcessData {
    pid: i32,
    name: String,
    status: Option<i32>,
    signal: Option<Signal>,
    dump: Option<bool>,
}

/// Blocks until the process with the specified PID exits.
///
/// # Arguments
/// * `pid` - The process ID of the process to wait for.
///
/// # Returns
/// * `Result<(), String>` - `Ok(())` if the process exits normally,
///   or an error message if something goes wrong.
pub fn wait_for_process_exit(
    mut process_data: ProcessData,
) -> Result<ProcessData, ProcNotifyError> {
    let pid = process_data.pid;
    let process_pid = Pid::from_raw(pid);

    match waitpid(process_pid, None) {
        Ok(WaitStatus::Exited(_, status)) => {
            process_data.status = Some(status);
            process_data.signal = None;
            Ok(process_data)
        }
        Ok(WaitStatus::Signaled(_, sig, dump)) => {
            process_data.status = None;
            process_data.signal = Some(sig);
            process_data.dump = Some(dump);
            Ok(process_data)
        }
        Ok(status) => Err(ProcNotifyError::RuntimeError(format!(
            "Unexpected wait status: {:?}",
            status
        ))),
        Err(err) => Err(ProcNotifyError::RuntimeError(format!(
            "Error while waiting for process: {}",
            err
        ))),
    }
}

fn find_processes(
    name: Option<String>,
    pid: Option<i32>,
) -> Result<ProcessData, errors::ProcNotifyError> {
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    if let Some(pid) = pid {
        let proc = sys
            .process(sysinfo::Pid::from(pid as usize))
            .ok_or(errors::ProcNotifyError::NoSuchProcess(pid.to_string()))?;
        let process_data = ProcessData {
            pid: pid,
            name: proc.name().to_string_lossy().to_string(),
            status: None,
            dump: None,
            signal: None,
        };
        return Ok(process_data);
    }

    if let Some(name) = name {
        for (pid, process) in sys.processes() {
            if let Some(exe_path) = process.exe() {
                if let Some(exe_name) = exe_path.file_name() {
                    if exe_name == Path::new(&name).as_os_str() {
                        let process_data = ProcessData {
                            pid: pid.as_u32() as i32,
                            name: exe_name.to_string_lossy().to_string(),
                            status: None,
                            dump: None,
                            signal: None,
                        };
                        return Ok(process_data);
                    }
                }
            }
        }
        return Err(errors::ProcNotifyError::NoSuchProcess(name.to_string()));
    }
    Err(errors::ProcNotifyError::NullSelection)
}

fn notify_user(email: &str, text: &str) -> Result<(), ProcNotifyError> {
    // Send an email to the specified address
    println!("Sending email to {}: {}", email, text);
    let to_address = email.parse::<Address>().map_err(|_| {
        ProcNotifyError::InvalidConfiguration(format!("invalid to address: {}", email))
    })?;

    let from = Mailbox {
        name: Some("Process Notifier".to_string()),
        email: FROM_ADDDRESS.parse().unwrap(),
    };
    let to = Mailbox {
        name: None,
        email: to_address,
    };
    // Create TLS transport on port 587 with STARTTLS
    let sender = SmtpTransport::starttls_relay("smtp.example.com")
        .map_err(|err| ProcNotifyError::RuntimeError(err.to_string()))?
        // Add credentials for authentication
        .credentials(Credentials::new(
            "username".to_owned(),
            "password".to_owned(),
        ))
        // Configure expected authentication mechanism
        .authentication(vec![Mechanism::Plain])
        .build();
    let message = lettre::Message::builder()
        .from(from)
        .to(to)
        .subject("Process exited")
        .body(text.to_string())
        .unwrap();

    sender.send(&message).map_err(|err| ProcNotifyError::RuntimeError(err.to_string()))?;

    Ok(())
}

fn make_error_message(process_data: ProcessData, err: ProcNotifyError) -> String {
    let process_str = format!("Process {} ({})", process_data.name, process_data.pid);
    let error_str = match err {
        ProcNotifyError::NullSelection => "No process selection criteria provided".to_string(),
        ProcNotifyError::NoSuchProcess(name) => format!("No such process: {}", name),
        ProcNotifyError::InvalidConfiguration(msg) => format!("Invalid configuration: {}", msg),
        ProcNotifyError::RuntimeError(msg) => format!("Runtime error: {}", msg),
    };
    format!("{}\n{}", process_str, error_str)
}

fn make_success_message(process_data: ProcessData) -> String {
    let process_str = format!("Process {} ({})", process_data.name, process_data.pid);
    match (
        process_data.status,
        process_data.signal,
        process_data.dump.unwrap_or(false),
    ) {
        (Some(status), _, _) => format!("{} exited with status {}", process_str, status),
        (_, Some(signal), dumped) => format!(
            "{} exited with signal {:?} {}",
            process_str,
            signal,
            if dumped { " and dumped core" } else { "" }
        ),
        (None, None, true) => format!("{} exited and dumped core", process_str),
        (None, None, false) => format!("{} exited", process_str),
    }
}

fn main() {
    let args = Args::parse();
    let process_data = find_processes(args.name, args.pid).unwrap_or_else(|_| {
        eprintln!("Error: Process not found");
        std::process::exit(1);
    });
    let message = match wait_for_process_exit(process_data.clone()) {
        Ok(process_data) => make_success_message(process_data),
        Err(err) => make_error_message(process_data, err),
    };
    notify_user(&args.email, &message).unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    });
}
