use std::thread;

use nix::{sys::wait::{waitpid, WaitStatus}, unistd::Pid};
use sysinfo::System;


use crate::{errors::ProcNotifyError, ProcessData};


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

#[cfg(target_os = "macos")]
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
pub fn wait_for_process_exit(
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
