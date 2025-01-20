use clap::Parser;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

mod errors;

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
}

/// Blocks until the process with the specified PID exits.
///
/// # Arguments
/// * `pid` - The process ID of the process to wait for.
///
/// # Returns
/// * `Result<(), String>` - `Ok(())` if the process exits normally,
///   or an error message if something goes wrong.
pub fn wait_for_process_exit(pid: i32) -> Result<(), String> {
    let process_pid = Pid::from_raw(pid);

    match waitpid(process_pid, None) {
        Ok(WaitStatus::Exited(_, _)) => Ok(()), // Process exited normally
        Ok(WaitStatus::Signaled(_, sig, _)) => Err(format!("Process was killed by signal: {:?}", sig)),
        Ok(status) => Err(format!("Unexpected wait status: {:?}", status)),
        Err(err) => Err(format!("Error while waiting for process: {}", err)),
    }
}

fn find_processes(name: Option<String>, pid: Option<i32>) -> Result<i32, errors::ProcNotifyError> {
    if let Some(pid) = pid {
        return Ok(pid);
    }

    if let Some(name) = name {
        // Find the PID of the process with the specified name
        // (this is just a placeholder implementation)
        Ok(12345)
    } else {
        Err(errors::ProcNotifyError::NullSelection)
    }
}

fn main() {
    let args = Args::parse();
    let pid = find_processes(args.name, args.pid).unwrap_or_else(|_| {
        eprintln!("Error: Process not found");
        std::process::exit(1);
    });
    match wait_for_process_exit(pid) {
        Ok(()) => println!("Process exited normally"),
        Err(err) => eprintln!("Error: {}", err),
    }
}
