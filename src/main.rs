use clap::Parser;
use errors::ProcNotifyError;
use kqueue::FilterFlag;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{Address, SmtpTransport, Transport};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::path::Path;
use std::{thread, time};
use sysinfo::{ProcessesToUpdate, System};
use tracing::{debug, error, info, warn, Level};

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
    #[arg(short, long, env = "PROCNOTIFY_EMAIL")]
    email: String,

    /// SMTP Port
    #[arg(long, default_value = "587", env = "PROCNOTIFY_SMTP_PORT")]
    smtp_port: u16,

    /// SMTP Server
    #[arg(long, env = "PROCNOTIFY_SMTP_SERVER")]
    smtp_server: String,

    /// SMTP Username
    #[arg(long, env = "PROCNOTIFY_SMTP_USERNAME")]
    smtp_username: String,

    /// SMTP Password
    #[arg(long, env = "PROCNOTIFY_SMTP_PASSWORD")]
    smtp_password: String,
}

#[derive(Debug, Clone)]
pub struct ProcessData {
    pid: i32,
    name: String,
    status: Option<i32>,
    signal: Option<Signal>,
    dump: Option<bool>,
    start_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl ProcessData {
    pub fn new(pid: i32, name: String) -> ProcessData {
        let mut system = System::new();
        system.refresh_all();
        let proc = system.process(sysinfo::Pid::from(pid as usize));
        let start_time = proc.map(|p| {
            chrono::DateTime::from_timestamp(p.start_time() as i64, 0).expect("invalid timestamp")
        });
        if start_time.is_none() {
            warn!("Failed to get start time for process {}", pid);
        }
        ProcessData {
            pid,
            name,
            start_time,
            status: None,
            signal: None,
            dump: None,
        }
    }
}

/// Blocks until the process with the specified PID exits.
///
/// # Arguments
/// * `pid` - The process ID of the process to wait for.
///
/// # Returns
/// * `Result<(), String>` - `Ok(())` if the process exits normally,
///   or an error message if something goes wrong.
pub fn wait_for_child_process_exit(
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

pub fn wait_for_process_exit_poll(
    process_data: ProcessData,
) -> Result<ProcessData, ProcNotifyError> {
    let sys = System::new();
    let pid = sysinfo::Pid::from_u32(process_data.pid as u32);
    loop {
        let proc = sys.process(pid);
        if proc.is_none() {
            break;
        }
        thread::sleep(time::Duration::from_secs(1));
    }
    Ok(process_data)
}

fn wait_for_process_exit_kqueue(process_data: ProcessData) -> Result<ProcessData, ProcNotifyError> {
    let mut watcher = kqueue::Watcher::new().map_err(|err| {
        ProcNotifyError::RuntimeError(format!("Failed to create kqueue: {}", err))
    })?;
    watcher
        .add_pid(
            process_data.pid,
            kqueue::EventFilter::EVFILT_PROC,
            FilterFlag::NOTE_EXIT,
        )
        .map_err(|err| {
            ProcNotifyError::RuntimeError(format!("Failed to add pid to kqueue: {}", err))
        })?;
    watcher.watch().map_err(|err| {
        ProcNotifyError::RuntimeError(format!("Failed to watch kqueue events: {}", err))
    })?;
    loop {
        let event = watcher.poll_forever(None);
        match event {
            Some(event) => match event.data {
                kqueue::EventData::Proc(e) => match e {
                    kqueue::Proc::Exit(status) => {
                        let process_data = ProcessData {
                            status: Some(status as i32),
                            ..process_data
                        };
                        return Ok(process_data);
                    }
                    _ => {
                        return Err(ProcNotifyError::RuntimeError(format!(
                            "Unexpected event data: {:?}",
                            e
                        )));
                    }
                },
                _ => {
                    return Err(ProcNotifyError::RuntimeError(format!(
                        "Unexpected event data: {:?}",
                        event.data
                    )));
                }
            },
            None => {
                return Err(ProcNotifyError::RuntimeError("No event data".to_string()));
            }
        }
    }
}

pub fn wait_for_process_exit_ptrace(
    process_data: ProcessData,
) -> Result<ProcessData, ProcNotifyError> {
    let pid = nix::unistd::Pid::from_raw(process_data.pid);
    nix::sys::ptrace::attach(pid).map_err(|err| {
        ProcNotifyError::RuntimeError(format!("Error attaching to process: {}", err))
    })?;
    nix::sys::wait::waitpid(pid, None).map_err(|err| {
        ProcNotifyError::RuntimeError(format!("Error waiting for process: {}", err))
    })?;
    nix::sys::ptrace::cont(pid, None).map_err(|err| {
        ProcNotifyError::RuntimeError(format!("Error continuing process: {}", err))
    })?;
    loop {
        let status = nix::sys::wait::waitpid(pid, None).map_err(|err| {
            ProcNotifyError::RuntimeError(format!("Error in waitpid loop: {}", err))
        })?;
        match status {
            WaitStatus::Exited(_, status) => {
                return Ok(ProcessData {
                    status: Some(status),
                    ..process_data
                });
            }
            WaitStatus::Signaled(_, signal, dumped) => {
                return Ok(ProcessData {
                    signal: Some(signal),
                    dump: Some(dumped),
                    ..process_data
                });
            }
            x => {
                debug!("wait loop: wait status: {:?}", x);
            }
        }
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
        let process_data = ProcessData::new(pid, proc.name().to_string_lossy().to_string());
        return Ok(process_data);
    }

    if let Some(name) = name {
        for (pid, process) in sys.processes() {
            if let Some(exe_path) = process.exe() {
                if let Some(exe_name) = exe_path.file_name() {
                    if exe_name == Path::new(&name).as_os_str() {
                        let process_data = ProcessData::new(
                            pid.as_u32() as i32,
                            exe_name.to_string_lossy().to_string(),
                        );
                        return Ok(process_data);
                    }
                }
            }
        }
        return Err(errors::ProcNotifyError::NoSuchProcess(name.to_string()));
    }
    Err(errors::ProcNotifyError::NullSelection)
}

fn notify_user(
    server: &str,
    username: &str,
    password: &str,
    email: &str,
    hostname: &str,
    text: &str,
) -> Result<(), ProcNotifyError> {
    // Send an email to the specified address
    info!("sending email to {}: {}", email, text);
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
    let sender = SmtpTransport::starttls_relay(server)
        .map_err(|err| ProcNotifyError::RuntimeError(err.to_string()))?
        // Add credentials for authentication
        .credentials(Credentials::new(username.to_owned(), password.to_owned()))
        // Configure expected authentication mechanism
        .authentication(vec![Mechanism::Plain])
        .build();
    let message = lettre::Message::builder()
        .from(from)
        .to(to)
        .subject(format!("Process exited on {}", hostname))
        .body(text.to_string())
        .unwrap();

    sender
        .send(&message)
        .map_err(|err| ProcNotifyError::RuntimeError(err.to_string()))?;

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
    let time_str = match process_data.start_time {
        Some(start_time) => {
            let duration = chrono::Utc::now().signed_duration_since(start_time);
            let total_seconds = duration.num_seconds();
            let hours = total_seconds / 3600;
            let minutes = (total_seconds % 3600) / 60;
            let seconds = total_seconds % 60;
            format!("started at {} and ran for {:02}h {:02}m {:02}s", start_time, hours, minutes, seconds)
        }
        None => "".to_string(),
    };
    let process_str = format!("Process {} ({}) {}", process_data.name, process_data.pid, time_str);
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
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    let args = Args::parse();
    let process_data = find_processes(args.name, args.pid).unwrap_or_else(|_| {
        error!("error: process not found");
        std::process::exit(1);
    });
    let message = match wait_for_process_exit_kqueue(process_data.clone()) {
        Ok(process_data) => make_success_message(process_data),
        Err(err) => {
            error!("error: {}", err);
            match err {
                ProcNotifyError::NoSuchProcess(_) => std::process::exit(1),
                ProcNotifyError::RuntimeError(e) => {
                    error!("runtime error: {}", e);
                    std::process::exit(1);
                }
                _ => {}
            }
            make_error_message(process_data, err)
        }
    };

    notify_user(
        &args.smtp_server,
        &args.smtp_username,
        &args.smtp_password,
        &args.email,
        &hostname::get().unwrap().to_string_lossy(),
        &message,
    )
    .unwrap_or_else(|err| {
        error!("error sending notification: {}", err);
        std::process::exit(1);
    });
}
