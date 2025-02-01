use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
};

use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::Pid,
};
use sysinfo::System;

use crate::{errors::ProcNotifyError, ProcessData};

/// Spawns a new process with the given command and arguments.
/// Captures stdout and stderr streams from the process.
///
/// # Arguments
/// * `command` - The command to execute
/// * `args` - Vector of arguments to pass to the command
///
/// # Returns
/// * `Result<ProcessData, ProcNotifyError>` - Process information including PID and output streams
pub fn spawn(command: &str, args: Vec<&str>) -> Result<ProcessData, ProcNotifyError> {
    let mut child = Command::new(command)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ProcNotifyError::RuntimeError(format!("Failed to spawn process: {}", e)))?;

    let pid = child.id() as i32;
    let name = command.to_string();

    // Get the stdout handle and spawn a thread to read it
    let mut stdout_handle = child.stdout.take().unwrap();
    let stdout_thread = thread::spawn(move || {
        let mut output = String::new();
        stdout_handle
            .read_to_string(&mut output)
            .expect("Failed to read stdout");
        output
    });

    // Get the stderr handle and spawn a thread to read it
    let mut stderr_handle = child.stderr.take().unwrap();
    let stderr_thread = thread::spawn(move || {
        let mut output = String::new();
        stderr_handle
            .read_to_string(&mut output)
            .expect("Failed to read stderr");
        output
    });

    // Create ProcessData with captured output
    let mut process_data = ProcessData::new(pid, name);
    process_data.stdout = Some(stdout_thread.join().unwrap());
    process_data.stderr = Some(stderr_thread.join().unwrap());

    Ok(process_data)
}

/// Blocks until the process with the specified PID exits.
///
/// # Arguments
/// * `pid` - The process ID of the process to wait for.
///
/// # Returns
/// * `Result<(), String>` - `Ok(())` if the process exits normally,
///   or an error message if something goes wrong.
/// Note: not used yet because there's no child process functionality
#[allow(dead_code)]
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

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub fn wait_for_process_exit(process_data: ProcessData) -> Result<ProcessData, ProcNotifyError> {
    use kqueue::FilterFlag;

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

/// Blocks until the process with the specified PID exits. Uses ptrace which is very invasive; not yet necessary.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn wait_for_process_exit_ptrace(
    process_data: ProcessData,
) -> Result<ProcessData, ProcNotifyError> {
    use tracing::debug;
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

#[cfg(target_os = "linux")]
pub fn wait_for_process_exit(process_data: ProcessData) -> Result<ProcessData, ProcNotifyError> {
    use nix::sys::signal::Signal;
    use tracing::warn;

    let mut monitor = cnproc::PidMonitor::new().map_err(|err| {
        ProcNotifyError::RuntimeError(format!("Error creating PidMonitor: {}", err))
    })?;
    loop {
        match monitor.recv() {
            Some(evt) => match evt {
                cnproc::PidEvent::Exit {
                    process_pid,
                    exit_code,
                    exit_signal,
                    ..
                } => {
                    if process_pid != process_data.pid {
                        continue;
                    }
                    let signal = if exit_signal == 0 {
                        None
                    } else {
                        Some(
                            Signal::try_from(exit_signal as i32)
                                .map_err(|x| ProcNotifyError::RuntimeError(x.to_string()))?,
                        )
                    };
                    return Ok(ProcessData {
                        status: Some(exit_code as i32),
                        signal,
                        ..process_data
                    });
                }
                // TODO: Determine if both exit and coredump events can be received for the same process
                cnproc::PidEvent::Coredump {
                    process_pid,
                    ..
                } => {
                    if process_pid != process_data.pid {
                        continue;
                    }
                    return Ok(ProcessData {
                        dump: Some(true),
                        ..process_data
                    });
                }
                _ => {
                    continue;
                }
            },
            None => {
                warn!("No event");
            }
        }
    }
}

/// Polls the system every second until the process with the specified PID exits.
/// This is a less invasive way to wait for a process to exit than using ptrace, but we can't get the exit status.
#[allow(dead_code)]
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
        thread::sleep(std::time::Duration::from_secs(1));
    }
    Ok(process_data)
}
