use std::{
    io::Read,
    process::{Command, Stdio},
    sync::{Arc, Mutex, Once},
    thread,
};

use lazy_static::lazy_static;

use nix::{
    sys::signal::Signal,
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
    // Create child process
    let mut child = Command::new(command)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ProcNotifyError::RuntimeError(format!("Failed to spawn process: {}", e)))?;

    let pid = child.id() as i32;
    let name = command.to_string();

    // Get the stdout and stderr handles before setting up signal handlers
    let mut stdout_handle = child.stdout.take().unwrap();
    let mut stderr_handle = child.stderr.take().unwrap();

    // Start the output capture threads
    let stdout_thread = thread::spawn(move || {
        let mut output = String::new();
        stdout_handle
            .read_to_string(&mut output)
            .expect("Failed to read stdout");
        output
    });

    let stderr_thread = thread::spawn(move || {
        let mut output = String::new();
        stderr_handle
            .read_to_string(&mut output)
            .expect("Failed to read stderr");
        output
    });

    // Now wrap the child process for signal handling
    let child_process = Arc::new(Mutex::new(child));

    // Set up signal handlers
    let signals = vec![
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGHUP,
        Signal::SIGQUIT,
    ];

    // Create a global static to store the child process
    lazy_static! {
        static ref CHILD_PROCESS: Mutex<Option<Arc<Mutex<std::process::Child>>>> = Mutex::new(None);
    }
    static INIT: Once = Once::new();

    // Store our child process in the static
    *CHILD_PROCESS.lock().unwrap() = Some(child_process.clone());

    extern "C" fn handle_signal(sig: libc::c_int) {
        if let Ok(guard) = CHILD_PROCESS.lock() {
            if let Some(child_process) = guard.as_ref() {
                if let Ok(mut child) = child_process.lock() {
                    // Kill child process
                    let _ = child.kill();
                    let _ = child.wait();
                }
                // Reset signal handler and re-raise
                unsafe {
                    libc::signal(sig, libc::SIG_DFL);
                    libc::raise(sig);
                }
            }
        }
    }

    // Set up signal handlers
    for &sig in signals.iter() {
        unsafe {
            libc::signal(sig as libc::c_int, handle_signal as libc::sighandler_t);
        }
    }

    // Set up cleanup to reset handlers
    INIT.call_once(|| {
        std::panic::set_hook(Box::new(move |_| {
            if let Ok(mut guard) = CHILD_PROCESS.lock() {
                // Reset all signal handlers
                for &sig in signals.iter() {
                    unsafe {
                        libc::signal(sig as libc::c_int, libc::SIG_DFL);
                    }
                }
                // Clear the static
                *guard = None;
            }
        }));
    });

    // Create ProcessData with captured output
    let mut process_data = ProcessData::new(pid, name);
    process_data.stdout = Some(stdout_thread.join().unwrap());
    process_data.stderr = Some(stderr_thread.join().unwrap());
    process_data.status = child_process.lock().unwrap().wait().unwrap().code();
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
