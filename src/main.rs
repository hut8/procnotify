use clap::Parser;
use errors::ProcNotifyError;
use lettre::message::{header, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::{Address, SmtpTransport, Transport};
use nix::sys::signal::Signal;
use process::wait_for_process_exit;
use std::path::Path;
use sysinfo::{ProcessesToUpdate, System};
use tracing::{error, info, warn, Level};
use chrono::{DateTime, Utc};

mod errors;
mod process;

#[derive(Parser, Debug)]
#[command(author, version, about = "Monitor a process and send an email notification when it exits")]
#[command(long_about = "Monitor a process and send an email notification when it exits. \
Either monitor an existing process using --name or --pid, or provide a command to execute.")]
struct Args {
    /// Name of the process to monitor (cannot be used with --pid or command)
    #[arg(short, long, conflicts_with_all = ["pid", "command"])]
    name: Option<String>,

    /// Process ID to monitor (cannot be used with --name or command)
    #[arg(short, long, conflicts_with_all = ["name", "command"])]
    pid: Option<i32>,

    /// Command and arguments to execute and monitor
    #[arg(trailing_var_arg = true, conflicts_with_all = ["name", "pid"])]
    command: Vec<String>,

    /// Email address to notify
    #[arg(short, long, env = "PROCNOTIFY_EMAIL")]
    email: String,

    /// Email address to send from (optional)
    #[arg(long, env = "PROCNOTIFY_FROM_EMAIL")]
    from_email: Option<String>,

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
    stdout: Option<String>,
    stderr: Option<String>,
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
            stdout: None,
            stderr: None,
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

fn get_from_address(username: &str, hostname: &str) -> Result<Address, ProcNotifyError> {
    // If username contains @, it's already a fully qualified email
    if username.contains('@') {
        return username.parse().map_err(|_| {
            ProcNotifyError::InvalidConfiguration(format!("invalid SMTP username as email: {}", username))
        });
    }

    // Otherwise append hostname
    format!("{}@{}", username, hostname)
        .parse()
        .map_err(|_| ProcNotifyError::InvalidConfiguration(
            format!("could not create valid email from SMTP username {} and hostname {}",
                username, hostname)
        ))
}

fn format_duration(start_time: DateTime<Utc>, end_time: DateTime<Utc>) -> String {
    let duration = end_time.signed_duration_since(start_time);
    let total_seconds = duration.num_seconds();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{:02}h {:02}m {:02}s", hours, minutes, seconds)
}

fn make_success_message(process_data: ProcessData) -> (String, String, String) {
    let end_time = chrono::Utc::now();
    let start_time = process_data.start_time.unwrap_or(end_time);
    let duration = format_duration(start_time, end_time);
    // Get hostname once at the start
    let hostname = hostname::get()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .to_string();

    let exit_status = match (
        process_data.status,
        process_data.signal,
        process_data.dump.unwrap_or(false),
    ) {
        (Some(status), _, _) => format!("Exited with status {}", status),
        (_, Some(signal), dumped) => format!(
            "Exited with signal {:?}{}",
            signal,
            if dumped { " and dumped core" } else { "" }
        ),
        (None, None, true) => "Exited and dumped core".to_string(),
        (None, None, false) => "Exited".to_string(),
    };

    let subject = format!(
        "Process '{}' {} on {} at {}",
        process_data.name,
        match (process_data.status, process_data.signal) {
            (Some(status), _) => format!("exited with status {}", status),
            (_, Some(signal)) => format!("exited with signal {:?}", signal),
            _ => "exited".to_string()
        },
        hostname,
        end_time.format("%Y-%m-%d %H:%M:%S")
    );

    let plaintext = format!(
        "Process Name: {}\n\
         Process ID: {} (on {})\n\
         Start Time: {}\n\
         End Time: {}\n\
         Duration: {}\n\
         Status: {}\n\
         {}{}",
        process_data.name,
        process_data.pid,
        hostname,
        start_time.format("%Y-%m-%dT%H:%M:%S%:z"),
        end_time.format("%Y-%m-%dT%H:%M:%S%:z"),
        duration,
        exit_status,
        if let Some(stdout) = &process_data.stdout {
            format!("\nStandard Output:\n{}", stdout)
        } else {
            String::new()
        },
        if let Some(stderr) = &process_data.stderr {
            format!("\nStandard Error:\n{}", stderr)
        } else {
            String::new()
        }
    );

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }}
        .container {{ max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .header {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .process-name {{ font-size: 24px; margin: 0; color: #333; }}
        .process-id {{ color: #666; margin: 5px 0; }}
        .details {{ margin: 15px 0; }}
        .detail-row {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #555; }}
        .status {{ padding: 8px; border-radius: 4px; display: inline-block; }}
        .output {{ background-color: #f8f9fa; padding: 10px; border-radius: 4px; white-space: pre-wrap; font-family: monospace; margin-top: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="process-name">{}</h1>
            <div class="process-id">Process ID: {} (on {})</div>
        </div>
        <div class="details">
            <div class="detail-row">
                <span class="label">Start Time:</span> {}</div>
            <div class="detail-row">
                <span class="label">End Time:</span> {}</div>
            <div class="detail-row">
                <span class="label">Duration:</span> {}</div>
            <div class="detail-row">
                <span class="label">Status:</span>
                <span class="status">{}</span>
            </div>
        </div>
        {}{}
    </div>
</body>
</html>"#,
        process_data.name,
        process_data.pid,
        hostname,
        start_time.format("%Y-%m-%dT%H:%M:%S%:z"),
        end_time.format("%Y-%m-%dT%H:%M:%S%:z"),
        duration,
        exit_status,
        if let Some(stdout) = &process_data.stdout {
            format!(
                r#"<div class="output">
                <div class="label">Standard Output:</div>
                <pre>{}</pre>
            </div>"#,
                stdout
            )
        } else {
            String::new()
        },
        if let Some(stderr) = &process_data.stderr {
            format!(
                r#"<div class="output">
                <div class="label">Standard Error:</div>
                <pre>{}</pre>
            </div>"#,
                stderr
            )
        } else {
            String::new()
        }
    );

    (plaintext, html, subject)
}

fn make_error_message(process_data: ProcessData, err: ProcNotifyError) -> (String, String, String) {
    let process_str = format!("Process {} ({})", process_data.name, process_data.pid);
    let error_str = match err {
        ProcNotifyError::NullSelection => "No process selection criteria provided. Use either --name or --pid to specify a process to monitor.".to_string(),
        ProcNotifyError::BothNameAndPid => "Cannot specify both --name and --pid. Use only one to identify the process to monitor.".to_string(),
        ProcNotifyError::InvalidCombination => "Cannot combine command execution with --name or --pid options".to_string(),
        ProcNotifyError::NoSuchProcess(name) => format!("No such process: {}", name),
        ProcNotifyError::InvalidConfiguration(msg) => format!("Invalid configuration: {}", msg),
        ProcNotifyError::RuntimeError(msg) => format!("Runtime error: {}", msg),
    };
    let text = format!("{}\n{}", process_str, error_str);
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }}
        .container {{ max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .error {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>{}</h2>
        <p class="error">{}</p>
    </div>
</body>
</html>"#,
        process_str, error_str
    );
    let subject = format!("Process '{}' monitoring error", process_data.name);
    (text, html, subject)
}

fn notify_user(
    server: &str,
    username: &str,
    password: &str,
    email: &str,
    hostname: &str,
    message: (&str, &str),
    subject: &str,
    from_email: Option<&str>,
) -> Result<(), ProcNotifyError> {
    let (text, html) = message;
    info!("sending email to {}", email);

    let to_address = email.parse::<Address>().map_err(|_| {
        ProcNotifyError::InvalidConfiguration(format!("invalid to address: {}", email))
    })?;

    let from_address = if let Some(from_email) = from_email {
        from_email.parse().map_err(|_| {
            ProcNotifyError::InvalidConfiguration(format!("invalid from address: {}", from_email))
        })?
    } else {
        get_from_address(username, hostname)?
    };

    let from = Mailbox {
        name: Some("Process Notifier".to_string()),
        email: from_address,
    };
    let to = Mailbox {
        name: None,
        email: to_address,
    };

    let email = lettre::Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(text.to_string())
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html.to_string())
                ),
        )
        .map_err(|err| ProcNotifyError::RuntimeError(err.to_string()))?;

    let sender = SmtpTransport::starttls_relay(server)
        .map_err(|err| ProcNotifyError::RuntimeError(err.to_string()))?
        .credentials(Credentials::new(username.to_owned(), password.to_owned()))
        .authentication(vec![Mechanism::Plain])
        .build();

    sender
        .send(&email)
        .map_err(|err| ProcNotifyError::RuntimeError(err.to_string()))?;

    Ok(())
}

fn validate_process_args(name: Option<String>, pid: Option<i32>, command: &[String]) -> Result<(), ProcNotifyError> {
    match (name, pid, command.is_empty()) {
        (None, None, true) => Err(ProcNotifyError::NullSelection),
        (Some(_), Some(_), _) => Err(ProcNotifyError::BothNameAndPid),
        (Some(_), _, false) | (_, Some(_), false) => Err(ProcNotifyError::InvalidCombination),
        _ => Ok(()),
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    let args = Args::parse();

    // Validate process selection arguments
    if let Err(err) = validate_process_args(args.name.clone(), args.pid, &args.command) {
        error!("Error: {}", err);
        std::process::exit(1);
    }

    let process_data = if !args.command.is_empty() {
        // Spawn mode: execute the command and monitor it
        let (cmd, cmd_args) = args.command.split_first().unwrap();
        process::spawn(cmd, cmd_args.iter().map(String::as_str).collect()).unwrap_or_else(|err| {
            error!("Error: {}", err);
            std::process::exit(1);
        })
    } else {
        // Monitor mode: find existing process
        find_processes(args.name, args.pid).unwrap_or_else(|err| {
            error!("Error: {}", err);
            std::process::exit(1);
        })
    };

    let message = match if !args.command.is_empty() {
        process::wait_for_child_process_exit(process_data.clone())
    } else {
        wait_for_process_exit(process_data.clone())
    } {
        Ok(process_data) => make_success_message(process_data),
        Err(err) => {
            error!("error: {}", err);
            match err {
                ProcNotifyError::NoSuchProcess(_) => std::process::exit(1),
                ProcNotifyError::RuntimeError(e) => {
                    error!("runtime error: {}", e);
                    std::process::exit(1);
                }
                ProcNotifyError::BothNameAndPid | ProcNotifyError::InvalidCombination => std::process::exit(1),
                _ => {}
            }
            make_error_message(process_data, err)
        }
    };

    // Get hostname once
    let hostname = hostname::get()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .to_string();

    notify_user(
        &args.smtp_server,
        &args.smtp_username,
        &args.smtp_password,
        &args.email,
        &hostname,
        (&message.0, &message.1),
        &message.2,
        args.from_email.as_deref(),
    )
    .unwrap_or_else(|err| {
        error!("error sending notification: {}", err);
        std::process::exit(1);
    });
}
