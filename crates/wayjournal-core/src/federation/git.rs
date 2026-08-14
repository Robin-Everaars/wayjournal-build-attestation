use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, process::CommandExt},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use rustix::process::{Pid, Signal, kill_process_group};
use thiserror::Error;

use crate::{
    LegacyEntry, LegacyEntrySource, LegacyStreamRequirement, MAX_BATCH_BYTES, MAX_RECORD_BYTES,
    PathClass, Store, classify_path,
    revision::CanonicalRevisionAccumulator,
    store::{
        Directory, MAX_CANONICAL_ENTRIES, MAX_TOTAL_CANONICAL_BYTES, RawFile,
        scan_after_streaming_legacy, scan_collected,
    },
};

use super::{GitObjectFormat, GitOid, GitSyncRequest};

const MAX_SMALL_OUTPUT: usize = 64 * 1024;
const MAX_TREE_OUTPUT: usize = 512 * 1024 * 1024;
const MAX_TREE_DIFF_OUTPUT: usize = 1024 * 1024 * 1024;
const MAX_TREE_RECORD_BYTES: usize = 512;
pub(super) const MAX_PENDING_REPO_OBJECTS: usize = 7_010_000;
pub(super) const MAX_PENDING_REPO_FS_ENTRIES: usize = 7_100_000;
pub(super) const MAX_PENDING_REPO_BYTES: u64 = 24 * 1024 * 1024 * 1024;
pub(super) const MAX_PENDING_REPO_DEPTH: usize = 64;
const GIT_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Debug, Error)]
#[error("Git {operation} failed: {message}")]
pub struct GitCommandError {
    pub(super) operation: &'static str,
    pub(super) message: String,
}
impl GitCommandError {
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    pub(super) fn is_hostile_repository_state(&self) -> bool {
        matches!(
            self.operation,
            "audit repository metadata"
                | "audit local config"
                | "bound fetched repository"
                | "read local branch"
                | "read object format"
                | "validate fetched object graph"
                | "inventory fetched objects"
                | "compact reachable synchronization objects"
                | "durably sync Git repository"
        )
    }
}

pub(super) struct GitRunner<'a> {
    request: &'a GitSyncRequest,
    timeout: Duration,
}
impl<'a> GitRunner<'a> {
    pub(super) const fn new(request: &'a GitSyncRequest) -> Self {
        Self {
            request,
            timeout: GIT_TIMEOUT,
        }
    }

    fn command(&self, cwd: &Directory, args: &[OsString]) -> Command {
        let mut command = Command::new(self.request.executable_proc_path());
        command
            .current_dir(cwd.proc_path())
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("HOME", "/dev/null")
            .env("XDG_CONFIG_HOME", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_AUTHOR_NAME", "Wayjournal")
            .env("GIT_AUTHOR_EMAIL", "wayjournal@example.invalid")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_COMMITTER_NAME", "Wayjournal")
            .env("GIT_COMMITTER_EMAIL", "wayjournal@example.invalid")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "never")
            .env("GIT_ASKPASS", "/bin/false")
            .env("SSH_ASKPASS", "/bin/false")
            .env("GIT_SSH_COMMAND", "/bin/false")
            .arg("--no-replace-objects")
            .arg("-c")
            .arg("credential.helper=")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("maintenance.auto=false")
            .arg("-c")
            .arg("maintenance.autoDetach=false")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("-c")
            .arg("gc.autoDetach=false")
            .arg("-c")
            .arg("commit.gpgSign=false")
            .arg("-c")
            .arg("tag.gpgSign=false")
            .arg("-c")
            .arg("protocol.ext.allow=never")
            .arg("-c")
            .arg(
                if self
                    .request
                    .approved_remote()
                    .locator()
                    .as_str()
                    .starts_with("file://")
                {
                    "protocol.file.allow=always"
                } else {
                    "protocol.file.allow=never"
                },
            )
            .arg("-c")
            .arg("fetch.fsckObjects=true")
            .arg("-c")
            .arg("transfer.fsckObjects=true")
            .args(args);
        command
    }

    pub(super) fn output(
        &self,
        operation: &'static str,
        cwd: &Directory,
        args: &[OsString],
        stdout_limit: usize,
    ) -> Result<Vec<u8>, GitCommandError> {
        let captured = self.status(operation, cwd, args, None, stdout_limit)?;
        if captured.status.success() {
            return Ok(captured.stdout);
        }
        Err(status_error(operation, captured.status))
    }

    pub(super) fn output_to_file(
        &self,
        operation: &'static str,
        cwd: &Directory,
        args: &[OsString],
        output: File,
        stdout_limit: usize,
    ) -> Result<usize, GitCommandError> {
        run_bounded_command_to_file(
            self.command(cwd, args),
            operation,
            output,
            stdout_limit,
            MAX_SMALL_OUTPUT,
            self.timeout,
        )
    }

    fn status(
        &self,
        operation: &'static str,
        cwd: &Directory,
        args: &[OsString],
        input: Option<&[u8]>,
        stdout_limit: usize,
    ) -> Result<CapturedOutput, GitCommandError> {
        let command = self.command(cwd, args);
        run_bounded_command_with_input(
            command,
            operation,
            input,
            stdout_limit,
            MAX_SMALL_OUTPUT,
            self.timeout,
        )
    }

    pub(super) fn succeeds(
        &self,
        operation: &'static str,
        cwd: &Directory,
        args: &[OsString],
    ) -> Result<bool, GitCommandError> {
        let captured = self.status(operation, cwd, args, None, MAX_SMALL_OUTPUT)?;
        if captured.status.success() {
            Ok(true)
        } else if captured.status.code().is_some() {
            Ok(false)
        } else {
            Err(status_error(operation, captured.status))
        }
    }
}

fn status_error(operation: &'static str, status: std::process::ExitStatus) -> GitCommandError {
    GitCommandError {
        operation,
        message: match status.code() {
            Some(code) => format!("command exited with status {code}"),
            None => "command terminated by signal".to_owned(),
        },
    }
}

#[derive(Debug)]
struct CapturedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    #[allow(dead_code)]
    stderr: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
#[allow(unsafe_code)]
fn run_bounded_command(
    command: Command,
    operation: &'static str,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<CapturedOutput, GitCommandError> {
    run_bounded_command_with_input(
        command,
        operation,
        None,
        stdout_limit,
        stderr_limit,
        timeout,
    )
}

#[allow(clippy::too_many_lines)]
#[allow(unsafe_code)]
fn run_bounded_command_to_file(
    mut command: Command,
    operation: &'static str,
    output: File,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<usize, GitCommandError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: the hook runs after fork and invokes only the async-signal-safe `umask(2)` syscall.
    unsafe {
        command.pre_exec(|| {
            rustix::process::umask(rustix::fs::Mode::empty());
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| GitCommandError {
        operation,
        message: error.to_string(),
    })?;
    let pid = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(pid, &mut child, true);
        return Err(GitCommandError {
            operation,
            message: "stdout pipe was not created".to_owned(),
        });
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(pid, &mut child, true);
        return Err(GitCommandError {
            operation,
            message: "stderr pipe was not created".to_owned(),
        });
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let (stdout_writer, stdout_rx) =
        spawn_bounded_file_writer(stdout, output, stdout_limit, Arc::clone(&overflow));
    let (stderr_reader, stderr_rx) =
        spawn_bounded_reader(stderr, stderr_limit, Arc::clone(&overflow));
    let started = Instant::now();
    let mut status = None;
    let mut written = None;
    let mut stderr = None;
    loop {
        if written.is_none() {
            match poll_writer(&stdout_rx, operation) {
                Ok(value) => written = value,
                Err(error) => {
                    terminate_process_group(pid, &mut child, status.is_none());
                    let _ = stdout_writer.join();
                    let _ = stderr_reader.join();
                    return Err(error);
                }
            }
        }
        if stderr.is_none() {
            match poll_reader(&stderr_rx, operation) {
                Ok(value) => stderr = value,
                Err(error) => {
                    terminate_process_group(pid, &mut child, status.is_none());
                    let _ = stdout_writer.join();
                    let _ = stderr_reader.join();
                    return Err(error);
                }
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(error) => {
                    terminate_process_group(pid, &mut child, true);
                    let _ = stdout_writer.join();
                    let _ = stderr_reader.join();
                    return Err(GitCommandError {
                        operation,
                        message: error.to_string(),
                    });
                }
            }
        }
        let failure = if overflow.load(Ordering::Acquire) {
            Some("bounded output exceeded")
        } else if started.elapsed() >= timeout {
            Some("operation timed out")
        } else {
            None
        };
        if let Some(message) = failure {
            terminate_process_group(pid, &mut child, status.is_none());
            let _ = stdout_writer.join();
            let _ = stderr_reader.join();
            return Err(GitCommandError {
                operation,
                message: message.to_owned(),
            });
        }
        if status.is_some() && written.is_some() && stderr.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    stdout_writer.join().map_err(|_| GitCommandError {
        operation,
        message: "stdout writer panicked".to_owned(),
    })?;
    stderr_reader.join().map_err(|_| GitCommandError {
        operation,
        message: "stderr reader panicked".to_owned(),
    })?;
    let status = status.expect("loop exits only after child status");
    if !status.success() {
        return Err(GitCommandError {
            operation,
            message: format!(
                "process exited with {status}: {}",
                String::from_utf8_lossy(&stderr.expect("loop exits only after stderr")).trim()
            ),
        });
    }
    Ok(written.expect("loop exits only after stdout"))
}

#[allow(clippy::too_many_lines)]
#[allow(unsafe_code)]
fn run_bounded_command_with_input(
    mut command: Command,
    operation: &'static str,
    input: Option<&[u8]>,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<CapturedOutput, GitCommandError> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: the hook runs after fork and invokes only the async-signal-safe `umask(2)` syscall.
    // The setting belongs solely to this Git process and its descendants; the parent is unchanged.
    unsafe {
        command.pre_exec(|| {
            rustix::process::umask(rustix::fs::Mode::empty());
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| GitCommandError {
        operation,
        message: error.to_string(),
    })?;
    let pid = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
    if let Some(bytes) = input {
        let Some(mut stdin) = child.stdin.take() else {
            terminate_process_group(pid, &mut child, true);
            return Err(GitCommandError {
                operation,
                message: "stdin pipe was not created".to_owned(),
            });
        };
        stdin.write_all(bytes).map_err(|error| {
            terminate_process_group(pid, &mut child, true);
            GitCommandError {
                operation,
                message: error.to_string(),
            }
        })?;
    }
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(pid, &mut child, true);
        return Err(GitCommandError {
            operation,
            message: "stdout pipe was not created".to_owned(),
        });
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(pid, &mut child, true);
        return Err(GitCommandError {
            operation,
            message: "stderr pipe was not created".to_owned(),
        });
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let (stdout_reader, stdout_rx) =
        spawn_bounded_reader(stdout, stdout_limit, Arc::clone(&overflow));
    let (stderr_reader, stderr_rx) =
        spawn_bounded_reader(stderr, stderr_limit, Arc::clone(&overflow));
    let started = Instant::now();
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if stdout.is_none() {
            match poll_reader(&stdout_rx, operation) {
                Ok(value) => stdout = value,
                Err(error) => {
                    terminate_process_group(pid, &mut child, status.is_none());
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(error);
                }
            }
        }
        if stderr.is_none() {
            match poll_reader(&stderr_rx, operation) {
                Ok(value) => stderr = value,
                Err(error) => {
                    terminate_process_group(pid, &mut child, status.is_none());
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(error);
                }
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(error) => {
                    terminate_process_group(pid, &mut child, true);
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(GitCommandError {
                        operation,
                        message: error.to_string(),
                    });
                }
            }
        }
        let failure = if overflow.load(Ordering::Acquire) {
            Some("bounded output exceeded")
        } else if started.elapsed() >= timeout {
            Some("operation timed out")
        } else {
            None
        };
        if let Some(message) = failure {
            terminate_process_group(pid, &mut child, status.is_none());
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(GitCommandError {
                operation,
                message: message.to_owned(),
            });
        }
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    stdout_reader.join().map_err(|_| GitCommandError {
        operation,
        message: "stdout reader panicked".to_owned(),
    })?;
    stderr_reader.join().map_err(|_| GitCommandError {
        operation,
        message: "stderr reader panicked".to_owned(),
    })?;
    Ok(CapturedOutput {
        status: status.expect("loop exits only after child status"),
        stdout: stdout.expect("loop exits only after stdout"),
        stderr: stderr.expect("loop exits only after stderr"),
    })
}

fn spawn_bounded_reader(
    mut pipe: impl Read + Send + 'static,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> (thread::JoinHandle<()>, Receiver<io::Result<Vec<u8>>>) {
    let (tx, rx) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let result = (|| {
            let mut output = Vec::new();
            let mut buffer = [0_u8; 8192];
            loop {
                let read = pipe.read(&mut buffer)?;
                if read == 0 {
                    return Ok(output);
                }
                let Some(next) = output.len().checked_add(read) else {
                    overflow.store(true, Ordering::Release);
                    return Ok(output);
                };
                if next > limit {
                    overflow.store(true, Ordering::Release);
                    return Ok(output);
                }
                output.extend_from_slice(&buffer[..read]);
            }
        })();
        let _ = tx.send(result);
    });
    (handle, rx)
}

fn spawn_bounded_file_writer(
    mut pipe: impl Read + Send + 'static,
    mut output: File,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> (thread::JoinHandle<()>, Receiver<io::Result<usize>>) {
    let (tx, rx) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let result = (|| {
            let mut written = 0_usize;
            let mut buffer = [0_u8; 8192];
            loop {
                let read = pipe.read(&mut buffer)?;
                if read == 0 {
                    output.flush()?;
                    return Ok(written);
                }
                let Some(next) = written.checked_add(read) else {
                    overflow.store(true, Ordering::Release);
                    return Ok(written);
                };
                if next > limit {
                    overflow.store(true, Ordering::Release);
                    return Ok(written);
                }
                output.write_all(&buffer[..read])?;
                written = next;
            }
        })();
        let _ = tx.send(result);
    });
    (handle, rx)
}

fn poll_writer(
    receiver: &Receiver<io::Result<usize>>,
    operation: &'static str,
) -> Result<Option<usize>, GitCommandError> {
    match receiver.try_recv() {
        Ok(Ok(bytes)) => Ok(Some(bytes)),
        Ok(Err(error)) => Err(GitCommandError {
            operation,
            message: error.to_string(),
        }),
        Err(TryRecvError::Empty) => Ok(None),
        Err(TryRecvError::Disconnected) => Err(GitCommandError {
            operation,
            message: "output writer disconnected".to_owned(),
        }),
    }
}

fn poll_reader(
    receiver: &Receiver<io::Result<Vec<u8>>>,
    operation: &'static str,
) -> Result<Option<Vec<u8>>, GitCommandError> {
    match receiver.try_recv() {
        Ok(Ok(bytes)) => Ok(Some(bytes)),
        Ok(Err(error)) => Err(GitCommandError {
            operation,
            message: error.to_string(),
        }),
        Err(TryRecvError::Empty) => Ok(None),
        Err(TryRecvError::Disconnected) => Err(GitCommandError {
            operation,
            message: "output reader disconnected".to_owned(),
        }),
    }
}

fn terminate_process_group(pid: Option<Pid>, child: &mut std::process::Child, child_running: bool) {
    if let Some(pid) = pid {
        let _ = kill_process_group(pid, Signal::KILL);
    }
    if child_running {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn command_error(operation: &'static str, error: impl std::fmt::Display) -> GitCommandError {
    GitCommandError {
        operation,
        message: error.to_string(),
    }
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

pub(super) struct LocalRepository {
    git_dir: Directory,
    pub format: GitObjectFormat,
    pub tip: GitOid,
}

pub(super) struct FetchedRepository {
    pub remote_tip: GitOid,
    bare: Directory,
    format: GitObjectFormat,
}

pub(super) struct SyncRepository {
    pub(super) bare: Directory,
    format: GitObjectFormat,
}

impl SyncRepository {
    pub(super) const fn format(&self) -> GitObjectFormat {
        self.format
    }

    pub(super) fn ref_oid(
        &self,
        runner: &GitRunner<'_>,
        reference: &str,
    ) -> Result<GitOid, GitCommandError> {
        let output = runner.output(
            "read synchronization ref",
            &self.bare,
            &repository_args(vec![
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from(reference),
            ]),
            MAX_SMALL_OUTPUT,
        )?;
        parse_oid_output(self.format, &output)
    }

    pub(super) fn commit_parents(
        &self,
        runner: &GitRunner<'_>,
        commit: &GitOid,
    ) -> Result<Vec<GitOid>, GitCommandError> {
        let output = runner.output(
            "read candidate parents",
            &self.bare,
            &repository_args(vec![
                OsString::from("rev-list"),
                OsString::from("--parents"),
                OsString::from("--max-count=1"),
                OsString::from(commit.as_hex()),
            ]),
            MAX_SMALL_OUTPUT,
        )?;
        let mut words = std::str::from_utf8(&output)
            .map_err(|_| GitCommandError {
                operation: "read candidate parents",
                message: "parent list is not UTF-8".to_owned(),
            })?
            .split_ascii_whitespace();
        let observed = words.next().ok_or_else(|| GitCommandError {
            operation: "read candidate parents",
            message: "parent list is empty".to_owned(),
        })?;
        if observed != commit.as_hex() {
            return Err(GitCommandError {
                operation: "read candidate parents",
                message: "parent list names a different commit".to_owned(),
            });
        }
        let mut parents = words
            .map(|word| {
                GitOid::parse(self.format, word).map_err(|error| GitCommandError {
                    operation: "read candidate parents",
                    message: error.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        parents.sort();
        parents.dedup();
        Ok(parents)
    }

    pub(super) fn is_ancestor(
        &self,
        runner: &GitRunner<'_>,
        ancestor: &GitOid,
        descendant: &GitOid,
    ) -> Result<bool, GitCommandError> {
        runner.succeeds(
            "validate commit ancestry",
            &self.bare,
            &repository_args(vec![
                OsString::from("merge-base"),
                OsString::from("--is-ancestor"),
                OsString::from(ancestor.as_hex()),
                OsString::from(descendant.as_hex()),
            ]),
        )
    }

    pub(super) fn immutable_edge_violation(
        &self,
        runner: &GitRunner<'_>,
        parent: &GitOid,
        child: &GitOid,
    ) -> Result<Option<super::GitQuarantineReason>, GitCommandError> {
        let mut output = self
            .bare
            .temporary_file()
            .map_err(|error| GitCommandError {
                operation: "validate immutable history edge",
                message: error.to_string(),
            })?;
        let retained = output.try_clone().map_err(|error| GitCommandError {
            operation: "validate immutable history edge",
            message: error.to_string(),
        })?;
        runner.output_to_file(
            "validate immutable history edge",
            &self.bare,
            &repository_args(vec![
                OsString::from("diff-tree"),
                OsString::from("-r"),
                OsString::from("--no-commit-id"),
                OsString::from("--name-status"),
                OsString::from("-z"),
                OsString::from("--no-renames"),
                OsString::from(parent.as_hex()),
                OsString::from(child.as_hex()),
                OsString::from("--"),
            ]),
            retained,
            MAX_TREE_OUTPUT,
        )?;
        output
            .seek(SeekFrom::Start(0))
            .map_err(|error| GitCommandError {
                operation: "validate immutable history edge",
                message: error.to_string(),
            })?;
        immutable_edge_violation_from_reader(std::io::BufReader::new(output))
    }

    pub(super) fn new_history(
        &self,
        runner: &GitRunner<'_>,
        boundary: &GitOid,
        local: &GitOid,
        remote: &GitOid,
        output_limit: usize,
    ) -> Result<Vec<u8>, GitCommandError> {
        runner.output(
            "enumerate new history",
            &self.bare,
            &repository_args(vec![
                OsString::from("rev-list"),
                OsString::from("--topo-order"),
                OsString::from("--reverse"),
                OsString::from("--parents"),
                OsString::from(local.as_hex()),
                OsString::from(remote.as_hex()),
                OsString::from("--not"),
                OsString::from(boundary.as_hex()),
            ]),
            output_limit,
        )
    }

    pub(super) fn require_commit_bounded(
        &self,
        runner: &GitRunner<'_>,
        oid: &GitOid,
        byte_limit: usize,
    ) -> Result<(), GitCommandError> {
        require_commit_object(runner, &self.bare, oid)?;
        let size = runner.output(
            "bound commit object",
            &self.bare,
            &repository_args(vec![
                OsString::from("cat-file"),
                OsString::from("-s"),
                OsString::from(oid.as_hex()),
            ]),
            MAX_SMALL_OUTPUT,
        )?;
        let size = std::str::from_utf8(&size)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .ok_or_else(|| GitCommandError {
                operation: "bound commit object",
                message: "commit size is not canonical decimal".to_owned(),
            })?;
        if size > byte_limit {
            return Err(GitCommandError {
                operation: "bound commit object",
                message: "commit object exceeds byte limit".to_owned(),
            });
        }
        Ok(())
    }

    pub(super) fn tree_snapshot(
        &self,
        store: &Store,
        runner: &GitRunner<'_>,
        oid: &GitOid,
    ) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
        tree_snapshot_streaming(store, runner, &self.bare, self.format, oid)
    }

    pub(super) fn spool_tree_additions(
        &self,
        runner: &GitRunner<'_>,
        local: &GitOid,
        candidate: &GitOid,
        output: File,
    ) -> Result<usize, GitCommandError> {
        if local.format() != self.format || candidate.format() != self.format {
            return Err(GitCommandError {
                operation: "enumerate candidate additions",
                message: "tree diff object format does not match repository".to_owned(),
            });
        }
        runner.output_to_file(
            "enumerate candidate additions",
            &self.bare,
            &repository_args(vec![
                OsString::from("diff-tree"),
                OsString::from("-r"),
                OsString::from("--no-commit-id"),
                OsString::from("--raw"),
                OsString::from("-z"),
                OsString::from("--no-renames"),
                OsString::from("--no-abbrev"),
                OsString::from(local.as_hex()),
                OsString::from(candidate.as_hex()),
                OsString::from("--"),
            ]),
            output,
            MAX_TREE_DIFF_OUTPUT,
        )
    }

    pub(super) fn tree_addition_source(
        &self,
        runner: &GitRunner<'_>,
        diff: File,
    ) -> Result<TreeAdditionSource, GitCommandError> {
        let command = runner.command(&self.bare, &repository_args(args(&["cat-file", "--batch"])));
        TreeAdditionSource::new(diff, self.format, command, runner.timeout)
    }
}

fn repository_args(tail: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut values = vec![OsString::from("--git-dir=.")];
    values.extend(tail);
    values
}

pub(super) fn inspect_local(
    store: &Store,
    runner: &GitRunner<'_>,
    request: &GitSyncRequest,
) -> Result<LocalRepository, GitCommandError> {
    let git_dir = store
        .root_dir
        .open_dir(OsStr::new(".git"))
        .map_err(|error| command_error("open local Git directory", error))?;
    inspect_local_anchored(runner, request, git_dir)
}

pub(super) fn inspect_local_anchored(
    runner: &GitRunner<'_>,
    request: &GitSyncRequest,
    git_dir: Directory,
) -> Result<LocalRepository, GitCommandError> {
    audit_local_config(runner, &git_dir)?;
    audit_repository_metadata(&git_dir)?;
    let branch = runner.output(
        "read local branch",
        &git_dir,
        &repository_args(args(&["symbolic-ref", "-q", "HEAD"])),
        MAX_SMALL_OUTPUT,
    )?;
    if branch.strip_suffix(b"\n") != Some(request.approved_remote().reference().as_str().as_bytes())
    {
        return Err(GitCommandError {
            operation: "read local branch",
            message: "checked-out branch is not the approved ref".to_owned(),
        });
    }
    let format_text = runner.output(
        "read object format",
        &git_dir,
        &repository_args(args(&["rev-parse", "--show-object-format"])),
        MAX_SMALL_OUTPUT,
    )?;
    let format = std::str::from_utf8(&format_text)
        .ok()
        .map(str::trim)
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| GitCommandError {
            operation: "read object format",
            message: "unsupported object format".to_owned(),
        })?;
    let local_tip_bytes = runner.output(
        "read local tip",
        &git_dir,
        &repository_args(args(&["rev-parse", "HEAD"])),
        MAX_SMALL_OUTPUT,
    )?;
    let tip = parse_oid_output(format, &local_tip_bytes)?;
    Ok(LocalRepository {
        git_dir,
        format,
        tip,
    })
}

pub(super) fn fetch_remote(
    runner: &GitRunner<'_>,
    request: &GitSyncRequest,
    attempt: &Directory,
    format: GitObjectFormat,
) -> Result<FetchedRepository, GitCommandError> {
    let (bare, created) = attempt
        .ensure_dir(OsStr::new("repo.git"))
        .map_err(|error| command_error("create admission repository", error))?;
    if !created {
        return Err(GitCommandError {
            operation: "create admission repository",
            message: "admission repository already exists".to_owned(),
        });
    }
    initialize_bare_repository(&bare, format)?;
    let refspec = format!(
        "+{}:refs/wayjournal/fetch/approved",
        request.approved_remote().reference().as_str()
    );
    let fetch_args = repository_args(vec![
        OsString::from("fetch"),
        OsString::from("--no-tags"),
        OsString::from("--no-write-fetch-head"),
        OsString::from(request.approved_remote().locator().as_str()),
        OsString::from(refspec),
    ]);
    runner.output("fetch approved ref", &bare, &fetch_args, MAX_SMALL_OUTPUT)?;
    audit_repository_metadata(&bare)?;
    audit_repository_physical_bounds(&bare)?;
    let remote_tip_bytes = runner.output(
        "read fetched tip",
        &bare,
        &repository_args(args(&["rev-parse", "refs/wayjournal/fetch/approved"])),
        MAX_SMALL_OUTPUT,
    )?;
    let remote_tip = parse_oid_output(format, &remote_tip_bytes)?;
    Ok(FetchedRepository {
        remote_tip,
        bare,
        format,
    })
}

#[allow(clippy::too_many_lines)]
pub(super) fn create_sync_repository(
    runner: &GitRunner<'_>,
    request: &GitSyncRequest,
    operation: &Directory,
    local: &LocalRepository,
) -> Result<(SyncRepository, GitOid, GitOid), GitCommandError> {
    // Network-controlled packs first land in a disposable repository. The durable repository is
    // fresh and imports only the closure reachable from the two authenticated authority refs.
    let (attempt, created) = operation
        .ensure_dir(OsStr::new("transfer-attempt"))
        .map_err(|error| command_error("create disposable synchronization attempt", error))?;
    if !created {
        return Err(GitCommandError {
            operation: "create disposable synchronization attempt",
            message: "synchronization attempt already exists".to_owned(),
        });
    }
    let (fetched, created) = attempt
        .ensure_dir(OsStr::new("repo.git"))
        .map_err(|error| command_error("create disposable fetched repository", error))?;
    if !created {
        return Err(GitCommandError {
            operation: "create disposable fetched repository",
            message: "fetched repository already exists".to_owned(),
        });
    }
    initialize_bare_repository(&fetched, local.format)?;
    let local_refspec = format!(
        "+{}:refs/wayjournal/local",
        request.approved_remote().reference().as_str()
    );
    runner.output(
        "fetch local synchronization tip",
        &fetched,
        &repository_args(vec![
            OsString::from("fetch"),
            OsString::from("--no-tags"),
            OsString::from("--no-write-fetch-head"),
            local.git_dir.child_proc_path().into_os_string(),
            OsString::from(local_refspec),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    let remote_refspec = format!(
        "+{}:refs/wayjournal/remote",
        request.approved_remote().reference().as_str()
    );
    runner.output(
        "fetch remote synchronization tip",
        &fetched,
        &repository_args(vec![
            OsString::from("fetch"),
            OsString::from("--no-tags"),
            OsString::from("--no-write-fetch-head"),
            OsString::from(request.approved_remote().locator().as_str()),
            OsString::from(remote_refspec),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    audit_repository_metadata(&fetched)?;
    audit_repository_physical_bounds(&fetched)?;
    super::fault::hit("disposable-fetch-complete");
    let fetched_repository = SyncRepository {
        bare: fetched,
        format: local.format,
    };
    let local_tip = fetched_repository.ref_oid(runner, "refs/wayjournal/local")?;
    let remote_tip = fetched_repository.ref_oid(runner, "refs/wayjournal/remote")?;
    verify_reachable_objects(runner, &fetched_repository)?;

    let (bare, created) = operation
        .ensure_dir(OsStr::new("repo.git"))
        .map_err(|error| command_error("create compact synchronization repository", error))?;
    if !created {
        return Err(GitCommandError {
            operation: "create compact synchronization repository",
            message: "compact synchronization repository already exists".to_owned(),
        });
    }
    initialize_bare_repository(&bare, local.format)?;
    for (source, destination) in [
        ("refs/wayjournal/local", "refs/wayjournal/local"),
        ("refs/wayjournal/remote", "refs/wayjournal/remote"),
    ] {
        runner.output(
            "compact reachable synchronization objects",
            &bare,
            &repository_args(vec![
                OsString::from("fetch"),
                OsString::from("--no-tags"),
                OsString::from("--no-write-fetch-head"),
                fetched_repository.bare.child_proc_path().into_os_string(),
                OsString::from(format!("+{source}:{destination}")),
            ]),
            MAX_SMALL_OUTPUT,
        )?;
    }
    runner.output(
        "bind synchronization HEAD",
        &bare,
        &repository_args(args(&[
            "update-ref",
            "refs/heads/wayjournal",
            "refs/wayjournal/local",
        ])),
        MAX_SMALL_OUTPUT,
    )?;
    let repository = SyncRepository {
        bare,
        format: local.format,
    };
    if repository.ref_oid(runner, "refs/wayjournal/local")? != local_tip
        || repository.ref_oid(runner, "refs/wayjournal/remote")? != remote_tip
    {
        return Err(GitCommandError {
            operation: "compact reachable synchronization objects",
            message: "compacted authority refs changed".to_owned(),
        });
    }
    verify_reachable_objects(runner, &repository)?;
    audit_repository_physical_bounds(&repository.bare)?;
    sync_directory_tree(&repository.bare, 0)?;
    super::fault::hit("compact-repository-durable");
    remove_directory_tree(
        &attempt,
        0,
        &mut MAX_PENDING_REPO_FS_ENTRIES.saturating_add(64),
    )?;
    operation
        .unlink_dir(OsStr::new("transfer-attempt"))
        .and_then(|()| operation.sync())
        .map_err(|error| command_error("retire disposable synchronization attempt", error))?;
    super::fault::hit("disposable-fetch-retired");
    Ok((repository, local_tip, remote_tip))
}

pub(super) fn open_sync_repository(
    operation: &Directory,
    format: GitObjectFormat,
) -> Result<SyncRepository, GitCommandError> {
    let bare = operation
        .open_dir(OsStr::new("repo.git"))
        .map_err(|error| command_error("open synchronization repository", error))?;
    audit_repository_metadata(&bare)?;
    audit_repository_physical_bounds(&bare)?;
    Ok(SyncRepository { bare, format })
}

fn verify_reachable_objects(
    runner: &GitRunner<'_>,
    repository: &SyncRepository,
) -> Result<(), GitCommandError> {
    let local = repository.ref_oid(runner, "refs/wayjournal/local")?;
    let remote = repository.ref_oid(runner, "refs/wayjournal/remote")?;
    runner.output(
        "validate fetched object graph",
        &repository.bare,
        &repository_args(vec![
            OsString::from("fsck"),
            OsString::from("--strict"),
            OsString::from("--connectivity-only"),
            OsString::from(local.as_hex()),
            OsString::from(remote.as_hex()),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    let mut objects = repository
        .bare
        .temporary_file()
        .map_err(|error| GitCommandError {
            operation: "inventory fetched objects",
            message: error.to_string(),
        })?;
    let retained = objects.try_clone().map_err(|error| GitCommandError {
        operation: "inventory fetched objects",
        message: error.to_string(),
    })?;
    runner.output_to_file(
        "inventory fetched objects",
        &repository.bare,
        &repository_args(args(&["rev-list", "--objects", "--all"])),
        retained,
        MAX_TREE_OUTPUT,
    )?;
    objects
        .seek(SeekFrom::Start(0))
        .map_err(|error| GitCommandError {
            operation: "inventory fetched objects",
            message: error.to_string(),
        })?;
    count_reachable_inventory(std::io::BufReader::new(objects), MAX_PENDING_REPO_OBJECTS)?;
    Ok(())
}

pub(super) fn select_candidate(
    runner: &GitRunner<'_>,
    repository: &SyncRepository,
    local_tip: &GitOid,
    remote_tip: &GitOid,
) -> Result<GitOid, GitCommandError> {
    let candidate = if repository.is_ancestor(runner, local_tip, remote_tip)? {
        remote_tip.clone()
    } else if repository.is_ancestor(runner, remote_tip, local_tip)? {
        local_tip.clone()
    } else {
        // `merge-tree --write-tree` performs the exact recursive path merge in Git's disk-backed
        // object/index machinery. Histories have already proved immutable parent edges, so the
        // only possible conflict is an unequal concurrent addition at the same exact path.
        let output = runner.output(
            "create union tree",
            &repository.bare,
            &repository_args(vec![
                OsString::from("merge-tree"),
                OsString::from("--write-tree"),
                OsString::from("--no-messages"),
                OsString::from(local_tip.as_hex()),
                OsString::from(remote_tip.as_hex()),
            ]),
            MAX_SMALL_OUTPUT,
        )?;
        let tree = parse_oid_output(repository.format, &output)?;
        let output = runner.output(
            "create union commit",
            &repository.bare,
            &repository_args(vec![
                OsString::from("commit-tree"),
                OsString::from(tree.as_hex()),
                OsString::from("-p"),
                OsString::from(local_tip.as_hex()),
                OsString::from("-p"),
                OsString::from(remote_tip.as_hex()),
                OsString::from("-m"),
                OsString::from("Wayjournal immutable union"),
            ]),
            MAX_SMALL_OUTPUT,
        )?;
        parse_oid_output(repository.format, &output)?
    };
    for tip in [local_tip, remote_tip] {
        if !repository.is_ancestor(runner, tip, &candidate)? {
            return Err(GitCommandError {
                operation: "validate union candidate ancestry",
                message: "candidate does not descend every admitted tip".to_owned(),
            });
        }
    }
    runner.output(
        "publish internal candidate ref",
        &repository.bare,
        &repository_args(vec![
            OsString::from("update-ref"),
            OsString::from("refs/wayjournal/candidate"),
            OsString::from(candidate.as_hex()),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    sync_repository_durable(runner, repository)?;
    Ok(candidate)
}

pub(super) fn advance_local_ref(
    runner: &GitRunner<'_>,
    request: &GitSyncRequest,
    local: &LocalRepository,
    repository: &SyncRepository,
    expected: &GitOid,
    candidate: &GitOid,
) -> Result<(), GitCommandError> {
    let current = inspect_local_ref(runner, local, request)?;
    if current == *candidate {
        sync_directory_tree(&local.git_dir, 0)?;
        require_local_commit(runner, local, candidate)?;
        return Ok(());
    }
    if current != *expected {
        return Err(GitCommandError {
            operation: "advance approved local ref",
            message: "approved local ref is neither expected old nor candidate".to_owned(),
        });
    }
    runner.output(
        "import synchronization candidate",
        &local.git_dir,
        &repository_args(vec![
            OsString::from("fetch"),
            OsString::from("--no-tags"),
            OsString::from("--no-write-fetch-head"),
            repository.bare.child_proc_path().into_os_string(),
            OsString::from("refs/wayjournal/candidate:refs/wayjournal/candidate"),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    require_local_commit(runner, local, candidate)?;
    runner.output(
        "advance approved local ref",
        &local.git_dir,
        &repository_args(vec![
            OsString::from("update-ref"),
            OsString::from(request.approved_remote().reference().as_str()),
            OsString::from(candidate.as_hex()),
            OsString::from(expected.as_hex()),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    super::fault::hit("local-ref-updated");
    // Git may update loose refs, packed refs, reflogs and object packs. Sync every retained
    // descendant and the repository root, then reopen the approved ref and candidate object.
    sync_directory_tree(&local.git_dir, 0)?;
    super::fault::hit("local-git-durable");
    if inspect_local_ref(runner, local, request)? != *candidate {
        return Err(GitCommandError {
            operation: "advance approved local ref",
            message: "approved local ref did not reach candidate after durable reopen".to_owned(),
        });
    }
    require_local_commit(runner, local, candidate)?;
    Ok(())
}

fn inspect_local_ref(
    runner: &GitRunner<'_>,
    local: &LocalRepository,
    request: &GitSyncRequest,
) -> Result<GitOid, GitCommandError> {
    let output = runner.output(
        "observe approved local ref",
        &local.git_dir,
        &repository_args(vec![
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from(request.approved_remote().reference().as_str()),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    parse_oid_output(local.format, &output)
}

pub(super) fn push_candidate_exact_lease(
    runner: &GitRunner<'_>,
    request: &GitSyncRequest,
    repository: &SyncRepository,
    expected_remote: &GitOid,
) -> Result<bool, GitCommandError> {
    let lease = format!(
        "--force-with-lease={}:{}",
        request.approved_remote().reference().as_str(),
        expected_remote.as_hex()
    );
    let refspec = format!(
        "refs/wayjournal/candidate:{}",
        request.approved_remote().reference().as_str()
    );
    runner.succeeds(
        "push synchronization candidate",
        &repository.bare,
        &repository_args(vec![
            OsString::from("push"),
            OsString::from("--porcelain"),
            OsString::from("--no-verify"),
            OsString::from(lease),
            OsString::from(request.approved_remote().locator().as_str()),
            OsString::from(refspec),
        ]),
    )
}

pub(super) fn observe_remote_ref(
    runner: &GitRunner<'_>,
    request: &GitSyncRequest,
    format: GitObjectFormat,
    cwd: &Directory,
) -> Result<Option<GitOid>, GitCommandError> {
    let output = runner.output(
        "observe approved remote ref",
        cwd,
        &[
            OsString::from("ls-remote"),
            OsString::from("--refs"),
            OsString::from(request.approved_remote().locator().as_str()),
            OsString::from(request.approved_remote().reference().as_str()),
        ],
        MAX_SMALL_OUTPUT,
    )?;
    let mut lines = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    if lines.next().is_some() {
        return Err(GitCommandError {
            operation: "observe approved remote ref",
            message: "remote returned multiple exact ref observations".to_owned(),
        });
    }
    let mut parts = line.split(|byte| *byte == b'\t');
    let oid = parts.next().unwrap_or_default();
    let reference = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || reference != request.approved_remote().reference().as_str().as_bytes()
    {
        return Err(GitCommandError {
            operation: "observe approved remote ref",
            message: "remote exact ref observation is malformed".to_owned(),
        });
    }
    let oid = std::str::from_utf8(oid).map_err(|_| GitCommandError {
        operation: "observe approved remote ref",
        message: "remote object id is not UTF-8".to_owned(),
    })?;
    GitOid::parse(format, oid)
        .map(Some)
        .map_err(|error| GitCommandError {
            operation: "observe approved remote ref",
            message: error.to_string(),
        })
}

pub(super) fn remove_internal_local_candidate(
    runner: &GitRunner<'_>,
    local: &LocalRepository,
) -> Result<(), GitCommandError> {
    let _ = runner.succeeds(
        "remove internal candidate ref",
        &local.git_dir,
        &repository_args(args(&["update-ref", "-d", "refs/wayjournal/candidate"])),
    )?;
    Ok(())
}

fn initialize_bare_repository(
    bare: &Directory,
    format: GitObjectFormat,
) -> Result<(), GitCommandError> {
    for name in ["hooks", "info", "objects", "refs"] {
        bare.ensure_dir(OsStr::new(name))
            .map_err(|error| command_error("initialize admission repository", error))?;
    }
    let objects = bare
        .open_dir(OsStr::new("objects"))
        .map_err(|error| command_error("initialize admission repository", error))?;
    for name in ["info", "pack"] {
        objects
            .ensure_dir(OsStr::new(name))
            .map_err(|error| command_error("initialize admission repository", error))?;
    }
    let refs = bare
        .open_dir(OsStr::new("refs"))
        .map_err(|error| command_error("initialize admission repository", error))?;
    for name in ["heads", "tags"] {
        refs.ensure_dir(OsStr::new(name))
            .map_err(|error| command_error("initialize admission repository", error))?;
    }
    let config = match format {
        GitObjectFormat::Sha1 => b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"
            .as_slice(),
        GitObjectFormat::Sha256 => b"[extensions]\n\tobjectformat = sha256\n[core]\n\trepositoryformatversion = 1\n\tfilemode = true\n\tbare = true\n"
            .as_slice(),
    };
    for (name, bytes) in [
        ("config", config),
        ("HEAD", b"ref: refs/heads/wayjournal\n".as_slice()),
    ] {
        let mut file = bare
            .create_file(OsStr::new(name))
            .map_err(|error| command_error("initialize admission repository", error))?;
        file.write_all(bytes)
            .map_err(|error| command_error("initialize admission repository", error))?;
        file.sync_all()
            .map_err(|error| command_error("initialize admission repository", error))?;
    }
    objects
        .sync()
        .and_then(|()| refs.sync())
        .and_then(|()| bare.sync())
        .map_err(|error| command_error("initialize admission repository", error))
}

fn audit_repository_metadata(git_dir: &Directory) -> Result<(), GitCommandError> {
    fn exists_regular(directory: &Directory, name: &OsStr) -> Result<bool, GitCommandError> {
        match directory.open_file(name) {
            Ok(_) => Ok(true),
            Err(crate::StoreError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(error) => Err(command_error("audit repository metadata", error)),
        }
    }
    let objects = git_dir
        .open_dir(OsStr::new("objects"))
        .map_err(|error| command_error("audit repository metadata", error))?;
    let info = objects
        .open_dir(OsStr::new("info"))
        .map_err(|error| command_error("audit repository metadata", error))?;
    if exists_regular(&info, OsStr::new("alternates"))?
        || exists_regular(git_dir, OsStr::new("shallow"))?
    {
        return Err(GitCommandError {
            operation: "audit repository metadata",
            message: "alternates or shallow history is not allowed".to_owned(),
        });
    }
    match git_dir.open_dir(OsStr::new("info")) {
        Ok(root_info) if exists_regular(&root_info, OsStr::new("grafts"))? => {
            return Err(GitCommandError {
                operation: "audit repository metadata",
                message: "grafts are not allowed".to_owned(),
            });
        }
        Ok(_) => {}
        Err(crate::StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(command_error("audit repository metadata", error)),
    }
    let refs = git_dir
        .open_dir(OsStr::new("refs"))
        .map_err(|error| command_error("audit repository metadata", error))?;
    match refs.open_dir(OsStr::new("replace")) {
        Ok(replace)
            if !replace
                .bounded_names(1)
                .map_err(|error| command_error("audit repository metadata", error))?
                .is_empty() =>
        {
            return Err(GitCommandError {
                operation: "audit repository metadata",
                message: "replace refs are not allowed".to_owned(),
            });
        }
        Ok(_) => {}
        Err(crate::StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(command_error("audit repository metadata", error)),
    }
    match git_dir.open_file(OsStr::new("packed-refs")) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take((MAX_SMALL_OUTPUT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|error| command_error("audit repository metadata", error))?;
            if bytes.len() > MAX_SMALL_OUTPUT
                || bytes.split(|byte| *byte == b'\n').any(|line| {
                    line.windows(b" refs/replace/".len())
                        .any(|window| window == b" refs/replace/")
                })
            {
                return Err(GitCommandError {
                    operation: "audit repository metadata",
                    message: "packed replace refs or oversized packed refs are not allowed"
                        .to_owned(),
                });
            }
        }
        Err(crate::StoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(command_error("audit repository metadata", error)),
    }
    Ok(())
}

pub(super) fn sync_repository_durable(
    runner: &GitRunner<'_>,
    repository: &SyncRepository,
) -> Result<(), GitCommandError> {
    audit_repository_metadata(&repository.bare)?;
    audit_repository_physical_bounds(&repository.bare)?;
    sync_directory_tree(&repository.bare, 0)?;
    // Reopen through the retained operation ancestry and prove Git can still resolve every
    // authority ref from the fsynced bytes, rather than trusting the just-mutated process state.
    for reference in [
        "refs/wayjournal/local",
        "refs/wayjournal/remote",
        "refs/wayjournal/candidate",
    ] {
        repository.ref_oid(runner, reference)?;
    }
    Ok(())
}

fn sync_directory_tree(directory: &Directory, depth: usize) -> Result<(), GitCommandError> {
    if depth > MAX_PENDING_REPO_DEPTH {
        return Err(GitCommandError {
            operation: "durably sync Git repository",
            message: "repository depth limit exceeded".to_owned(),
        });
    }
    directory
        .for_each_name(MAX_PENDING_REPO_FS_ENTRIES, |name| {
            let os_name = OsStr::from_bytes(name);
            match directory.kind(os_name)? {
                rustix::fs::FileType::Directory => {
                    let child = directory.open_dir(os_name)?;
                    sync_directory_tree(&child, depth + 1).map_err(|error| {
                        crate::store::invalid_layout(&child.path, &error.to_string())
                    })?;
                }
                rustix::fs::FileType::RegularFile => {
                    let file = directory.open_file(os_name)?;
                    file.sync_all().map_err(|error| {
                        crate::store::io_error(
                            "sync Git repository file",
                            &directory.path.join(os_name),
                            error,
                        )
                    })?;
                }
                _ => {
                    return Err(crate::store::invalid_layout(
                        &directory.path,
                        "Git repository contains non-regular entry",
                    ));
                }
            }
            Ok(())
        })
        .map_err(|error| command_error("durably sync Git repository", error))?;
    directory
        .sync()
        .map_err(|error| command_error("durably sync Git repository", error))
}

fn remove_directory_tree(
    directory: &Directory,
    depth: usize,
    budget: &mut usize,
) -> Result<(), GitCommandError> {
    if depth > MAX_PENDING_REPO_DEPTH {
        return Err(GitCommandError {
            operation: "retire disposable synchronization attempt",
            message: "attempt depth limit exceeded".to_owned(),
        });
    }
    loop {
        if *budget == 0 {
            return Err(GitCommandError {
                operation: "retire disposable synchronization attempt",
                message: "attempt entry limit exceeded".to_owned(),
            });
        }
        let names = directory
            .name_batch((*budget).min(4_096))
            .map_err(|error| command_error("retire disposable synchronization attempt", error))?;
        if names.is_empty() {
            return directory.sync().map_err(|error| {
                command_error("retire disposable synchronization attempt", error)
            });
        }
        for name in names {
            *budget -= 1;
            let os_name = OsStr::from_bytes(&name);
            if directory.kind(os_name).map_err(|error| {
                command_error("retire disposable synchronization attempt", error)
            })? == rustix::fs::FileType::Directory
            {
                let child = directory.open_dir(os_name).map_err(|error| {
                    command_error("retire disposable synchronization attempt", error)
                })?;
                remove_directory_tree(&child, depth + 1, budget)?;
                directory.unlink_dir(os_name).map_err(|error| {
                    command_error("retire disposable synchronization attempt", error)
                })?;
            } else {
                directory.unlink_file(os_name).map_err(|error| {
                    command_error("retire disposable synchronization attempt", error)
                })?;
            }
        }
        directory
            .sync()
            .map_err(|error| command_error("retire disposable synchronization attempt", error))?;
    }
}

fn audit_repository_physical_bounds(git_dir: &Directory) -> Result<(), GitCommandError> {
    fn walk(
        directory: &Directory,
        depth: usize,
        entries: &mut usize,
        bytes: &mut u64,
        objects: &mut usize,
        below_objects: bool,
    ) -> Result<(), GitCommandError> {
        if depth > MAX_PENDING_REPO_DEPTH {
            return Err(GitCommandError {
                operation: "bound fetched repository",
                message: "repository depth limit exceeded".to_owned(),
            });
        }
        let remaining = MAX_PENDING_REPO_FS_ENTRIES.saturating_sub(*entries);
        directory
            .for_each_name(remaining.saturating_add(1), |name| {
                *entries = entries.checked_add(1).ok_or_else(|| {
                    crate::store::invalid_layout(&directory.path, "repository entry count overflow")
                })?;
                if *entries > MAX_PENDING_REPO_FS_ENTRIES {
                    return Err(crate::store::invalid_layout(
                        &directory.path,
                        "repository entry limit exceeded",
                    ));
                }
                let os_name = OsStr::from_bytes(name);
                match directory.kind(os_name)? {
                    rustix::fs::FileType::Directory => {
                        let child = directory.open_dir(os_name)?;
                        let is_objects = below_objects || (depth == 0 && name == b"objects");
                        walk(&child, depth + 1, entries, bytes, objects, is_objects).map_err(
                            |error| crate::store::invalid_layout(&child.path, &error.to_string()),
                        )?;
                    }
                    rustix::fs::FileType::RegularFile => {
                        let file = directory.open_file(os_name)?;
                        let length = directory.require_regular(&file, os_name)?;
                        *bytes = bytes.checked_add(length).ok_or_else(|| {
                            crate::store::invalid_layout(
                                &directory.path,
                                "repository byte count overflow",
                            )
                        })?;
                        if *bytes > MAX_PENDING_REPO_BYTES {
                            return Err(crate::store::invalid_layout(
                                &directory.path,
                                "repository byte limit exceeded",
                            ));
                        }
                        if below_objects {
                            *objects = objects.checked_add(1).ok_or_else(|| {
                                crate::store::invalid_layout(
                                    &directory.path,
                                    "repository object count overflow",
                                )
                            })?;
                            if *objects > MAX_PENDING_REPO_OBJECTS {
                                return Err(crate::store::invalid_layout(
                                    &directory.path,
                                    "repository object limit exceeded",
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(crate::store::invalid_layout(
                            &directory.path,
                            "repository contains a non-regular entry",
                        ));
                    }
                }
                Ok(())
            })
            .map_err(|error| command_error("bound fetched repository", error))
    }
    let mut entries = 0;
    let mut bytes = 0;
    let mut objects = 0;
    walk(git_dir, 0, &mut entries, &mut bytes, &mut objects, false)
}

fn audit_local_config(runner: &GitRunner<'_>, git_dir: &Directory) -> Result<(), GitCommandError> {
    let output = runner.output(
        "audit local config",
        git_dir,
        &repository_args(args(&["config", "--local", "--name-only", "-z", "--list"])),
        MAX_SMALL_OUTPUT,
    )?;
    for raw in output
        .split(|byte| *byte == 0)
        .filter(|key| !key.is_empty())
    {
        let key = String::from_utf8_lossy(raw).to_ascii_lowercase();
        let allowed = matches!(
            key.as_str(),
            "core.repositoryformatversion"
                | "core.filemode"
                | "core.bare"
                | "core.logallrefupdates"
                | "core.ignorecase"
                | "core.precomposeunicode"
                | "extensions.objectformat"
                | "user.name"
                | "user.email"
        );
        if !allowed {
            return Err(GitCommandError {
                operation: "audit local config",
                message: format!("unsafe local Git config key: {key}"),
            });
        }
    }
    Ok(())
}

fn parse_oid_output(format: GitObjectFormat, output: &[u8]) -> Result<GitOid, GitCommandError> {
    let text = std::str::from_utf8(output).map_err(|_| GitCommandError {
        operation: "parse object id",
        message: "non-UTF-8 object id".to_owned(),
    })?;
    GitOid::parse(format, text.trim()).map_err(|error| GitCommandError {
        operation: "parse object id",
        message: error.to_string(),
    })
}

fn require_commit_object(
    runner: &GitRunner<'_>,
    git_dir: &Directory,
    oid: &GitOid,
) -> Result<(), GitCommandError> {
    let object_type = runner.output(
        "validate commit object",
        git_dir,
        &repository_args(vec![
            OsString::from("cat-file"),
            OsString::from("-t"),
            OsString::from(oid.as_hex()),
        ]),
        MAX_SMALL_OUTPUT,
    )?;
    if object_type != b"commit\n" {
        return Err(GitCommandError {
            operation: "validate commit object",
            message: "approved object is not a commit".to_owned(),
        });
    }
    Ok(())
}

pub(super) fn require_local_commit(
    runner: &GitRunner<'_>,
    repository: &LocalRepository,
    oid: &GitOid,
) -> Result<(), GitCommandError> {
    require_commit_object(runner, &repository.git_dir, oid)
}

pub(super) fn require_fetched_commit(
    runner: &GitRunner<'_>,
    repository: &FetchedRepository,
    oid: &GitOid,
) -> Result<(), GitCommandError> {
    require_commit_object(runner, &repository.bare, oid)
}

pub(super) fn require_sync_commit(
    runner: &GitRunner<'_>,
    repository: &SyncRepository,
    oid: &GitOid,
) -> Result<(), GitCommandError> {
    require_commit_object(runner, &repository.bare, oid)
}

pub(super) fn local_tree_snapshot(
    store: &Store,
    runner: &GitRunner<'_>,
    repository: &LocalRepository,
    oid: &GitOid,
) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
    tree_snapshot(store, runner, &repository.git_dir, repository.format, oid)
}

pub(super) fn local_tree_snapshot_streaming(
    store: &Store,
    runner: &GitRunner<'_>,
    repository: &LocalRepository,
    oid: &GitOid,
) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
    tree_snapshot_streaming(store, runner, &repository.git_dir, repository.format, oid)
}

pub(super) fn fetched_tree_snapshot(
    store: &Store,
    runner: &GitRunner<'_>,
    repository: &FetchedRepository,
    oid: &GitOid,
) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
    tree_snapshot(store, runner, &repository.bare, repository.format, oid)
}

fn tree_snapshot(
    store: &Store,
    runner: &GitRunner<'_>,
    git_dir: &Directory,
    format: GitObjectFormat,
    oid: &GitOid,
) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
    let files = tree_files(store, runner, git_dir, format, oid)?;
    scan_collected(store, &files, Vec::new()).map_err(Into::into)
}

fn tree_snapshot_streaming(
    store: &Store,
    runner: &GitRunner<'_>,
    git_dir: &Directory,
    format: GitObjectFormat,
    oid: &GitOid,
) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
    let source = tree_file_source(runner, git_dir, format, oid)?;
    scan_streamed_tree(store, source)
}

fn tree_file_source(
    runner: &GitRunner<'_>,
    git_dir: &Directory,
    format: GitObjectFormat,
    oid: &GitOid,
) -> Result<TreeFileSource, super::GitAdmissionError> {
    if oid.format() != format {
        return Err(super::GitAdmissionError::CheckpointObjectFormatMismatch);
    }
    let mut listing = git_dir.temporary_file()?;
    let output = listing
        .try_clone()
        .map_err(|source| super::GitAdmissionError::Io {
            operation: "retain canonical tree listing",
            source,
        })?;
    let command = runner.command(
        git_dir,
        &repository_args(vec![
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            OsString::from(oid.as_hex()),
        ]),
    );
    run_bounded_command_to_file(
        command,
        "spool canonical tree listing",
        output,
        MAX_TREE_OUTPUT,
        MAX_SMALL_OUTPUT,
        runner.timeout,
    )?;
    listing
        .seek(SeekFrom::Start(0))
        .map_err(|source| super::GitAdmissionError::Io {
            operation: "rewind canonical tree listing",
            source,
        })?;
    let blob_command = runner.command(git_dir, &repository_args(args(&["cat-file", "--batch"])));
    TreeFileSource::new(listing, format, blob_command, runner.timeout).map_err(Into::into)
}

fn scan_streamed_tree(
    store: &Store,
    mut tree: TreeFileSource,
) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
    let mut revision = CanonicalRevisionAccumulator::new();
    let mut legacy = TreeLegacySource {
        tree: &mut tree,
        revision: &mut revision,
        current: None,
        first_journal: None,
        source_error: None,
        reached_journal: false,
    };
    let validation =
        store.validate_legacy_stream(LegacyStreamRequirement::FullDomainBounded, &mut legacy);
    if let Some(error) = legacy.source_error.take() {
        return Err(error);
    }
    let mut unconsumed = false;
    loop {
        match legacy.next_entry() {
            Ok(Some(_)) => unconsumed = true,
            Ok(None) => break,
            Err(_) => {
                if let Some(error) = legacy.source_error.take() {
                    return Err(error);
                }
                return Err(crate::StoreError::Corrupt {
                    issue: crate::StoreCorruption::InvalidLegacy {
                        message: "legacy source failed while checking exhaustion".to_owned(),
                    },
                }
                .into());
            }
        }
    }
    if validation.is_ok() && unconsumed {
        return Err(crate::StoreError::Corrupt {
            issue: crate::StoreCorruption::InvalidLegacy {
                message: "bounded legacy adapter did not consume every legacy entry".to_owned(),
            },
        }
        .into());
    }
    validation?;
    let first_journal = legacy.first_journal.take();
    drop(legacy);
    let mut journal_files = Vec::new();
    if let Some(file) = first_journal {
        journal_files.push(file);
    }
    while let Some(file) = tree.next_file()? {
        if !matches!(
            classify_path(&file.path),
            PathClass::JournalRecord | PathClass::JournalBatch
        ) {
            return Err(super::GitAdmissionError::InvalidTreeEntry);
        }
        revision
            .push(&file.path, &file.bytes)
            .map_err(|error| GitCommandError {
                operation: "compute streamed tree revision",
                message: error.to_string(),
            })?;
        journal_files.push(file);
    }
    tree.finish()?;
    scan_after_streaming_legacy(store, &journal_files, revision.finish()).map_err(Into::into)
}

struct TreeListingEntry {
    path: Vec<u8>,
    blob: GitOid,
    class: PathClass,
}

struct TreeListingCursor<R> {
    reader: R,
    format: GitObjectFormat,
    entry_budget: crate::store::CanonicalEntryBudget,
    previous_path: Option<Vec<u8>>,
}
impl<R: BufRead> TreeListingCursor<R> {
    const fn new(reader: R, format: GitObjectFormat) -> Self {
        Self {
            reader,
            format,
            entry_budget: crate::store::CanonicalEntryBudget::new(),
            previous_path: None,
        }
    }

    fn next_entry(&mut self) -> Result<Option<TreeListingEntry>, super::GitAdmissionError> {
        let Some(record) = read_nul_record(&mut self.reader, MAX_TREE_RECORD_BYTES)? else {
            return Ok(None);
        };
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| GitCommandError {
                operation: "parse tree",
                message: "tree entry has no path separator".to_owned(),
            })?;
        let (metadata, path_with_tab) = record.split_at(separator);
        let path = &path_with_tab[1..];
        let mut parts = metadata.split(|byte| *byte == b' ');
        let mode = parts.next().unwrap_or_default();
        let kind = parts.next().unwrap_or_default();
        let blob = parts.next().unwrap_or_default();
        if mode != b"100644" || kind != b"blob" || parts.next().is_some() {
            return Err(super::GitAdmissionError::InvalidTreeEntry);
        }
        let class = classify_path(path);
        if !matches!(
            class,
            PathClass::LegacyEvent
                | PathClass::LegacyBatch
                | PathClass::JournalRecord
                | PathClass::JournalBatch
        ) {
            return Err(super::GitAdmissionError::NonCanonicalTrackedPath);
        }
        if self
            .previous_path
            .as_deref()
            .is_some_and(|previous| previous >= path)
        {
            return Err(super::GitAdmissionError::InvalidTreeEntry);
        }
        let blob = std::str::from_utf8(blob).map_err(|_| GitCommandError {
            operation: "parse tree",
            message: "blob id is not UTF-8".to_owned(),
        })?;
        let blob = GitOid::parse(self.format, blob).map_err(|error| GitCommandError {
            operation: "parse tree",
            message: error.to_string(),
        })?;
        self.entry_budget
            .push_sorted_file(path, MAX_CANONICAL_ENTRIES)
            .map_err(|()| GitCommandError {
                operation: "parse tree",
                message: "canonical entry-count limit exceeded".to_owned(),
            })?;
        self.previous_path = Some(path.to_vec());
        Ok(Some(TreeListingEntry {
            path: path.to_vec(),
            blob,
            class,
        }))
    }
}

struct TreeDiffCursor<R> {
    reader: R,
    format: GitObjectFormat,
    entries: usize,
    previous_path: Option<Vec<u8>>,
}

impl<R: BufRead> TreeDiffCursor<R> {
    fn new(reader: R, format: GitObjectFormat) -> Self {
        Self {
            reader,
            format,
            entries: 0,
            previous_path: None,
        }
    }

    fn next_addition(&mut self) -> Result<Option<TreeListingEntry>, super::GitAdmissionError> {
        let Some(metadata) = read_nul_record(&mut self.reader, MAX_TREE_RECORD_BYTES)? else {
            return Ok(None);
        };
        let path = read_nul_record(&mut self.reader, MAX_TREE_RECORD_BYTES)?.ok_or_else(|| {
            GitCommandError {
                operation: "parse tree diff",
                message: "tree diff ended before an addition path".to_owned(),
            }
        })?;
        if self.entries >= MAX_CANONICAL_ENTRIES {
            return Err(GitCommandError {
                operation: "parse tree diff",
                message: "canonical entry-count limit exceeded".to_owned(),
            }
            .into());
        }
        let mut parts = metadata.split(|byte| *byte == b' ');
        let old_mode = parts.next().unwrap_or_default();
        let new_mode = parts.next().unwrap_or_default();
        let old_blob = parts.next().unwrap_or_default();
        let new_blob = parts.next().unwrap_or_default();
        let status = parts.next().unwrap_or_default();
        if old_mode != b":000000"
            || new_mode != b"100644"
            || old_blob.len() != self.format.hex_len()
            || !old_blob.iter().all(|byte| *byte == b'0')
            || status != b"A"
            || parts.next().is_some()
        {
            return Err(super::GitAdmissionError::InvalidTreeEntry);
        }
        let class = classify_path(&path);
        if !matches!(
            class,
            PathClass::LegacyEvent
                | PathClass::LegacyBatch
                | PathClass::JournalRecord
                | PathClass::JournalBatch
        ) {
            return Err(super::GitAdmissionError::NonCanonicalTrackedPath);
        }
        if self
            .previous_path
            .as_deref()
            .is_some_and(|previous| previous >= path.as_slice())
        {
            return Err(super::GitAdmissionError::InvalidTreeEntry);
        }
        let new_blob = std::str::from_utf8(new_blob).map_err(|_| GitCommandError {
            operation: "parse tree diff",
            message: "blob id is not UTF-8".to_owned(),
        })?;
        let blob = GitOid::parse(self.format, new_blob).map_err(|error| GitCommandError {
            operation: "parse tree diff",
            message: error.to_string(),
        })?;
        self.entries += 1;
        self.previous_path = Some(path.clone());
        Ok(Some(TreeListingEntry { path, blob, class }))
    }
}

pub(super) struct TreeAdditionSource {
    cursor: TreeDiffCursor<std::io::BufReader<File>>,
    blobs: CatFileBatch,
}

impl TreeAdditionSource {
    fn new(
        diff: File,
        format: GitObjectFormat,
        blob_command: Command,
        timeout: Duration,
    ) -> Result<Self, GitCommandError> {
        Ok(Self {
            cursor: TreeDiffCursor::new(std::io::BufReader::new(diff), format),
            blobs: CatFileBatch::spawn(blob_command, timeout)?,
        })
    }

    pub(super) fn next_file(&mut self) -> Result<Option<RawFile>, super::GitAdmissionError> {
        let Some(entry) = self.cursor.next_addition()? else {
            return Ok(None);
        };
        let byte_limit = canonical_blob_limit(entry.class)
            .ok_or(super::GitAdmissionError::NonCanonicalTrackedPath)?;
        let bytes = self.blobs.read_blob(&entry.blob, byte_limit)?;
        Ok(Some(RawFile {
            path: entry.path,
            bytes,
        }))
    }

    pub(super) fn totals(mut self) -> Result<(usize, u64), super::GitAdmissionError> {
        let mut count = 0_usize;
        let mut total_bytes = 0_u64;
        while let Some(file) = self.next_file()? {
            count = count.checked_add(1).ok_or_else(|| GitCommandError {
                operation: "count candidate additions",
                message: "addition count overflow".to_owned(),
            })?;
            total_bytes = total_bytes
                .checked_add(
                    u64::try_from(file.bytes.len()).map_err(|_| GitCommandError {
                        operation: "count candidate additions",
                        message: "addition byte count exceeds u64".to_owned(),
                    })?,
                )
                .ok_or_else(|| GitCommandError {
                    operation: "count candidate additions",
                    message: "addition byte count overflow".to_owned(),
                })?;
            if total_bytes > MAX_TOTAL_CANONICAL_BYTES {
                return Err(GitCommandError {
                    operation: "count candidate additions",
                    message: "addition bytes exceed the canonical store limit".to_owned(),
                }
                .into());
            }
        }
        self.finish()?;
        Ok((count, total_bytes))
    }

    pub(super) fn finish(self) -> Result<(), GitCommandError> {
        self.blobs.finish()
    }
}

struct TreeFileSource {
    cursor: TreeListingCursor<std::io::BufReader<File>>,
    blobs: CatFileBatch,
    total_bytes: u64,
}

impl TreeFileSource {
    fn new(
        listing: File,
        format: GitObjectFormat,
        blob_command: Command,
        timeout: Duration,
    ) -> Result<Self, GitCommandError> {
        Ok(Self {
            cursor: TreeListingCursor::new(std::io::BufReader::new(listing), format),
            blobs: CatFileBatch::spawn(blob_command, timeout)?,
            total_bytes: 0,
        })
    }

    fn next_file(&mut self) -> Result<Option<RawFile>, super::GitAdmissionError> {
        let Some(entry) = self.cursor.next_entry()? else {
            return Ok(None);
        };
        let byte_limit = canonical_blob_limit(entry.class)
            .ok_or(super::GitAdmissionError::NonCanonicalTrackedPath)?;
        let bytes = self.blobs.read_blob(&entry.blob, byte_limit)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| GitCommandError {
                operation: "read streamed canonical tree",
                message: "canonical byte count exceeds u64".to_owned(),
            })?)
            .ok_or_else(|| GitCommandError {
                operation: "read streamed canonical tree",
                message: "canonical byte count overflow".to_owned(),
            })?;
        if self.total_bytes > MAX_TOTAL_CANONICAL_BYTES {
            return Err(GitCommandError {
                operation: "read streamed canonical tree",
                message: "canonical aggregate byte limit exceeded".to_owned(),
            }
            .into());
        }
        Ok(Some(RawFile {
            path: entry.path,
            bytes,
        }))
    }

    fn finish(self) -> Result<(), GitCommandError> {
        self.blobs.finish()
    }
}

struct TreeLegacySource<'a> {
    tree: &'a mut TreeFileSource,
    revision: &'a mut CanonicalRevisionAccumulator,
    current: Option<RawFile>,
    first_journal: Option<RawFile>,
    source_error: Option<super::GitAdmissionError>,
    reached_journal: bool,
}

impl LegacyEntrySource for TreeLegacySource<'_> {
    fn next_entry(&mut self) -> Result<Option<LegacyEntry<'_>>, String> {
        if self.reached_journal {
            return Ok(None);
        }
        self.current = None;
        let file = match self.tree.next_file() {
            Ok(Some(file)) => file,
            Ok(None) => {
                self.reached_journal = true;
                return Ok(None);
            }
            Err(error) => {
                self.source_error = Some(error);
                return Err("canonical Git tree source failed".to_owned());
            }
        };
        if let Err(error) = self.revision.push(&file.path, &file.bytes) {
            self.source_error = Some(
                GitCommandError {
                    operation: "compute streamed tree revision",
                    message: error.to_string(),
                }
                .into(),
            );
            return Err("canonical Git tree revision failed".to_owned());
        }
        match classify_path(&file.path) {
            class @ (PathClass::LegacyEvent | PathClass::LegacyBatch) => {
                self.current = Some(file);
                let current = self.current.as_ref().expect("current legacy entry");
                Ok(Some(LegacyEntry::new(&current.path, &current.bytes, class)))
            }
            PathClass::JournalRecord | PathClass::JournalBatch => {
                self.first_journal = Some(file);
                self.reached_journal = true;
                Ok(None)
            }
            PathClass::NonCanonical | PathClass::InvalidReserved => {
                self.source_error = Some(super::GitAdmissionError::NonCanonicalTrackedPath);
                Err("canonical Git tree path classification failed".to_owned())
            }
        }
    }
}

fn canonical_blob_limit(class: PathClass) -> Option<usize> {
    match class {
        PathClass::LegacyEvent | PathClass::LegacyBatch => Some(crate::MAX_LEGACY_FILE_BYTES),
        PathClass::JournalRecord => Some(MAX_RECORD_BYTES),
        PathClass::JournalBatch => Some(MAX_BATCH_BYTES),
        _ => None,
    }
}

fn count_reachable_inventory(
    mut reader: impl BufRead,
    limit: usize,
) -> Result<usize, GitCommandError> {
    let mut count = 0_usize;
    while read_delimited_record(
        &mut reader,
        b'\n',
        MAX_TREE_RECORD_BYTES,
        "inventory fetched objects",
        "reachable object inventory ended inside a record",
        "reachable object inventory record length overflow",
        "reachable object inventory record exceeds byte limit",
    )?
    .is_some()
    {
        count = count.checked_add(1).ok_or_else(|| GitCommandError {
            operation: "inventory fetched objects",
            message: "reachable object count overflow".to_owned(),
        })?;
        if count > limit {
            return Err(GitCommandError {
                operation: "inventory fetched objects",
                message: "reachable object count exceeds bound".to_owned(),
            });
        }
    }
    Ok(count)
}

fn immutable_edge_violation_from_reader(
    mut reader: impl BufRead,
) -> Result<Option<super::GitQuarantineReason>, GitCommandError> {
    while let Some(status) = read_delimited_record(
        &mut reader,
        0,
        MAX_TREE_RECORD_BYTES,
        "validate immutable history edge",
        "immutable edge diff ended inside a status",
        "immutable edge diff status length overflow",
        "immutable edge diff status exceeds byte limit",
    )? {
        read_delimited_record(
            &mut reader,
            0,
            MAX_TREE_RECORD_BYTES,
            "validate immutable history edge",
            "immutable edge diff ended inside a path",
            "immutable edge diff path length overflow",
            "immutable edge diff path exceeds byte limit",
        )?
        .ok_or_else(|| GitCommandError {
            operation: "validate immutable history edge",
            message: "immutable edge diff ended before a path".to_owned(),
        })?;
        if status.first() == Some(&b'D') {
            return Ok(Some(super::GitQuarantineReason::Deletion));
        }
        if status.first() == Some(&b'M') {
            return Ok(Some(super::GitQuarantineReason::Modification));
        }
    }
    Ok(None)
}

fn read_nul_record(
    reader: &mut impl BufRead,
    limit: usize,
) -> Result<Option<Vec<u8>>, GitCommandError> {
    read_delimited_record(
        reader,
        0,
        limit,
        "stream canonical tree",
        "tree listing ended inside a record",
        "tree record length overflow",
        "tree record exceeds byte limit",
    )
}

fn read_delimited_record(
    reader: &mut impl BufRead,
    delimiter: u8,
    limit: usize,
    operation: &'static str,
    truncated_message: &'static str,
    overflow_message: &'static str,
    limit_message: &'static str,
) -> Result<Option<Vec<u8>>, GitCommandError> {
    let mut record = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|error| GitCommandError {
            operation,
            message: error.to_string(),
        })?;
        if available.is_empty() {
            return if record.is_empty() {
                Ok(None)
            } else {
                Err(GitCommandError {
                    operation,
                    message: truncated_message.to_owned(),
                })
            };
        }
        let delimiter = available.iter().position(|byte| *byte == delimiter);
        let take = delimiter.unwrap_or(available.len());
        let length = record
            .len()
            .checked_add(take)
            .ok_or_else(|| GitCommandError {
                operation,
                message: overflow_message.to_owned(),
            })?;
        if length > limit {
            return Err(GitCommandError {
                operation,
                message: limit_message.to_owned(),
            });
        }
        record.extend_from_slice(&available[..take]);
        let terminated = delimiter.is_some();
        reader.consume(take + usize::from(terminated));
        if terminated {
            return Ok(Some(record));
        }
    }
}

fn read_cat_file_response(
    reader: &mut impl BufRead,
    expected: &GitOid,
    byte_limit: usize,
) -> Result<Vec<u8>, GitCommandError> {
    const OPERATION: &str = "read canonical blob batch";
    const HEADER_LIMIT: usize = 256;
    let header = read_delimited_record(
        reader,
        b'\n',
        HEADER_LIMIT,
        OPERATION,
        "cat-file ended inside a response header",
        "cat-file response header length overflow",
        "cat-file response header exceeds byte limit",
    )?
    .ok_or_else(|| GitCommandError {
        operation: OPERATION,
        message: "cat-file ended before a response header".to_owned(),
    })?;
    let mut parts = header.split(|byte| *byte == b' ');
    let oid = parts.next().unwrap_or_default();
    let kind = parts.next().unwrap_or_default();
    let size = parts.next().unwrap_or_default();
    if oid != expected.as_hex().as_bytes() || kind != b"blob" || parts.next().is_some() {
        return Err(GitCommandError {
            operation: OPERATION,
            message: "cat-file response does not match the requested blob".to_owned(),
        });
    }
    if size.is_empty()
        || (size.len() > 1 && size[0] == b'0')
        || !size.iter().all(u8::is_ascii_digit)
    {
        return Err(GitCommandError {
            operation: OPERATION,
            message: "cat-file blob length is not canonical decimal".to_owned(),
        });
    }
    let size = std::str::from_utf8(size)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| GitCommandError {
            operation: OPERATION,
            message: "cat-file blob length exceeds usize".to_owned(),
        })?;
    if size > byte_limit {
        return Err(GitCommandError {
            operation: OPERATION,
            message: "cat-file blob exceeds byte limit".to_owned(),
        });
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|error| GitCommandError {
            operation: OPERATION,
            message: error.to_string(),
        })?;
    bytes.resize(size, 0);
    reader
        .read_exact(&mut bytes)
        .map_err(|error| GitCommandError {
            operation: OPERATION,
            message: error.to_string(),
        })?;
    let mut terminator = [0_u8; 1];
    reader
        .read_exact(&mut terminator)
        .map_err(|error| GitCommandError {
            operation: OPERATION,
            message: error.to_string(),
        })?;
    if terminator != *b"\n" {
        return Err(GitCommandError {
            operation: OPERATION,
            message: "cat-file blob has an invalid terminator".to_owned(),
        });
    }
    Ok(bytes)
}

struct CatFileRequest {
    expected: GitOid,
    byte_limit: usize,
}

#[cfg(test)]
static CAT_FILE_RESPONSE_SEND_HOOK: std::sync::Mutex<Option<(String, Arc<std::sync::Barrier>)>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn install_cat_file_response_send_hook(expected: &GitOid, barrier: Arc<std::sync::Barrier>) {
    *CAT_FILE_RESPONSE_SEND_HOOK.lock().expect("hook lock") =
        Some((expected.as_hex().to_owned(), barrier));
}

#[cfg(test)]
fn clear_cat_file_response_send_hook() {
    *CAT_FILE_RESPONSE_SEND_HOOK.lock().expect("hook lock") = None;
}

#[cfg(test)]
fn wait_for_cat_file_response_send_hook(expected: &GitOid) {
    let barrier = CAT_FILE_RESPONSE_SEND_HOOK
        .lock()
        .expect("hook lock")
        .as_ref()
        .filter(|(oid, _)| oid == expected.as_hex())
        .map(|(_, barrier)| Arc::clone(barrier));
    if let Some(barrier) = barrier {
        barrier.wait();
    }
}

struct CatFileBatch {
    child: std::process::Child,
    pid: Option<Pid>,
    stdin: Option<std::process::ChildStdin>,
    request_tx: Option<mpsc::SyncSender<CatFileRequest>>,
    response_rx: Receiver<Result<Vec<u8>, GitCommandError>>,
    response_reader: Option<thread::JoinHandle<()>>,
    stderr_rx: Receiver<io::Result<Vec<u8>>>,
    stderr_reader: Option<thread::JoinHandle<()>>,
    stderr_overflow: Arc<AtomicBool>,
    timeout: Duration,
    finished: bool,
}
impl CatFileBatch {
    #[allow(unsafe_code)]
    fn spawn(mut command: Command, timeout: Duration) -> Result<Self, GitCommandError> {
        const OPERATION: &str = "start canonical blob batch";
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        // SAFETY: the hook runs after fork and invokes only the async-signal-safe `umask(2)`
        // syscall. The setting belongs solely to this process tree.
        unsafe {
            command.pre_exec(|| {
                rustix::process::umask(rustix::fs::Mode::empty());
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|error| GitCommandError {
            operation: OPERATION,
            message: error.to_string(),
        })?;
        let pid = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
        let Some(stdin) = child.stdin.take() else {
            terminate_process_group(pid, &mut child, true);
            return Err(GitCommandError {
                operation: OPERATION,
                message: "stdin pipe was not created".to_owned(),
            });
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_process_group(pid, &mut child, true);
            return Err(GitCommandError {
                operation: OPERATION,
                message: "stdout pipe was not created".to_owned(),
            });
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_process_group(pid, &mut child, true);
            return Err(GitCommandError {
                operation: OPERATION,
                message: "stderr pipe was not created".to_owned(),
            });
        };
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let (stderr_reader, stderr_rx) =
            spawn_bounded_reader(stderr, MAX_SMALL_OUTPUT, Arc::clone(&stderr_overflow));
        let (request_tx, request_rx) = mpsc::sync_channel::<CatFileRequest>(1);
        let (response_tx, response_rx) = mpsc::sync_channel::<Result<Vec<u8>, GitCommandError>>(1);
        let response_reader = thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            while let Ok(request) = request_rx.recv() {
                let response =
                    read_cat_file_response(&mut reader, &request.expected, request.byte_limit);
                #[cfg(test)]
                wait_for_cat_file_response_send_hook(&request.expected);
                let failed = response.is_err();
                if response_tx.send(response).is_err() || failed {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            pid,
            stdin: Some(stdin),
            request_tx: Some(request_tx),
            response_rx,
            response_reader: Some(response_reader),
            stderr_rx,
            stderr_reader: Some(stderr_reader),
            stderr_overflow,
            timeout,
            finished: false,
        })
    }

    fn read_blob(
        &mut self,
        expected: &GitOid,
        byte_limit: usize,
    ) -> Result<Vec<u8>, GitCommandError> {
        const OPERATION: &str = "read canonical blob batch";
        if self.finished {
            return Err(GitCommandError {
                operation: OPERATION,
                message: "cat-file batch is closed".to_owned(),
            });
        }
        let request = CatFileRequest {
            expected: expected.clone(),
            byte_limit,
        };
        if self
            .request_tx
            .as_ref()
            .ok_or_else(|| GitCommandError {
                operation: OPERATION,
                message: "cat-file request channel is closed".to_owned(),
            })?
            .send(request)
            .is_err()
        {
            let error = GitCommandError {
                operation: OPERATION,
                message: "cat-file request reader disconnected".to_owned(),
            };
            self.abort();
            return Err(error);
        }
        let write_result = (|| {
            let stdin = self.stdin.as_mut().ok_or_else(|| GitCommandError {
                operation: OPERATION,
                message: "cat-file stdin is closed".to_owned(),
            })?;
            stdin
                .write_all(expected.as_hex().as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush())
                .map_err(|error| GitCommandError {
                    operation: OPERATION,
                    message: error.to_string(),
                })
        })();
        if let Err(error) = write_result {
            self.abort();
            return Err(error);
        }
        let started = Instant::now();
        loop {
            if self.stderr_overflow.load(Ordering::Acquire) {
                let error = GitCommandError {
                    operation: OPERATION,
                    message: "bounded stderr exceeded".to_owned(),
                };
                self.abort();
                return Err(error);
            }
            match self.response_rx.recv_timeout(Duration::from_millis(5)) {
                Ok(Ok(bytes)) => return Ok(bytes),
                Ok(Err(error)) => {
                    self.abort();
                    return Err(error);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let error = GitCommandError {
                        operation: OPERATION,
                        message: "cat-file response reader disconnected".to_owned(),
                    };
                    self.abort();
                    return Err(error);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if started.elapsed() >= self.timeout {
                let error = GitCommandError {
                    operation: OPERATION,
                    message: "operation timed out".to_owned(),
                };
                self.abort();
                return Err(error);
            }
        }
    }

    fn finish(mut self) -> Result<(), GitCommandError> {
        const OPERATION: &str = "finish canonical blob batch";
        self.request_tx.take();
        self.stdin.take();
        let started = Instant::now();
        let mut status = None;
        let mut stderr = None;
        loop {
            if stderr.is_none() {
                match poll_reader(&self.stderr_rx, OPERATION) {
                    Ok(value) => stderr = value,
                    Err(error) => {
                        self.abort();
                        return Err(error);
                    }
                }
            }
            if status.is_none() {
                match self.child.try_wait() {
                    Ok(value) => status = value,
                    Err(error) => {
                        let error = GitCommandError {
                            operation: OPERATION,
                            message: error.to_string(),
                        };
                        self.abort();
                        return Err(error);
                    }
                }
            }
            let failure = if self.stderr_overflow.load(Ordering::Acquire) {
                Some("bounded stderr exceeded")
            } else if started.elapsed() >= self.timeout {
                Some("operation timed out")
            } else {
                None
            };
            if let Some(message) = failure {
                let error = GitCommandError {
                    operation: OPERATION,
                    message: message.to_owned(),
                };
                self.abort();
                return Err(error);
            }
            if status.is_some() && stderr.is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.finished = true;
        self.response_reader
            .take()
            .expect("open batch owns response reader")
            .join()
            .map_err(|_| GitCommandError {
                operation: OPERATION,
                message: "cat-file response reader panicked".to_owned(),
            })?;
        self.stderr_reader
            .take()
            .expect("open batch owns stderr reader")
            .join()
            .map_err(|_| GitCommandError {
                operation: OPERATION,
                message: "cat-file stderr reader panicked".to_owned(),
            })?;
        let status = status.expect("finish waits for child status");
        let stderr = stderr.expect("finish waits for stderr");
        if !status.success() {
            return Err(GitCommandError {
                operation: OPERATION,
                message: format!(
                    "process exited with {status}: {}",
                    String::from_utf8_lossy(&stderr).trim()
                ),
            });
        }
        Ok(())
    }

    fn abort(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.request_tx.take();
        self.stdin.take();
        let running = self.child.try_wait().ok().flatten().is_none();
        terminate_process_group(self.pid, &mut self.child, running);
        if let Some(reader) = self.response_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}
impl Drop for CatFileBatch {
    fn drop(&mut self) {
        self.abort();
    }
}

#[allow(clippy::too_many_lines)]
#[allow(unsafe_code)]
fn stream_tree_listing(
    mut command: Command,
    format: GitObjectFormat,
    timeout: Duration,
    mut visit: impl FnMut(TreeListingEntry) -> Result<(), super::GitAdmissionError>,
) -> Result<(), super::GitAdmissionError> {
    const OPERATION: &str = "stream canonical tree";
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: the hook runs after fork and invokes only the async-signal-safe `umask(2)` syscall.
    // The setting belongs solely to this Git process and its descendants; the parent is unchanged.
    unsafe {
        command.pre_exec(|| {
            rustix::process::umask(rustix::fs::Mode::empty());
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| GitCommandError {
        operation: OPERATION,
        message: error.to_string(),
    })?;
    let pid = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
    let Some(stdout) = child.stdout.take() else {
        terminate_process_group(pid, &mut child, true);
        return Err(GitCommandError {
            operation: OPERATION,
            message: "stdout pipe was not created".to_owned(),
        }
        .into());
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_process_group(pid, &mut child, true);
        return Err(GitCommandError {
            operation: OPERATION,
            message: "stderr pipe was not created".to_owned(),
        }
        .into());
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let (stderr_reader, stderr_rx) =
        spawn_bounded_reader(stderr, MAX_SMALL_OUTPUT, Arc::clone(&overflow));
    let (entry_tx, entry_rx) = mpsc::sync_channel(1);
    let listing_reader = thread::spawn(move || {
        let mut cursor = TreeListingCursor::new(std::io::BufReader::new(stdout), format);
        loop {
            let next = cursor.next_entry();
            let finished = !matches!(&next, Ok(Some(_)));
            if entry_tx.send(next).is_err() || finished {
                break;
            }
        }
    });

    let mut status = None;
    let mut stderr = None;
    let mut stream_error = None;
    let mut listing_done = false;
    let mut last_progress = Instant::now();
    while !listing_done && stream_error.is_none() {
        if overflow.load(Ordering::Acquire) {
            stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
                operation: OPERATION,
                message: "bounded stderr exceeded".to_owned(),
            }));
            break;
        }
        if last_progress.elapsed() >= timeout {
            stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
                operation: OPERATION,
                message: "operation timed out".to_owned(),
            }));
            break;
        }
        match entry_rx.recv_timeout(Duration::from_millis(5)) {
            Ok(Ok(Some(entry))) => {
                last_progress = Instant::now();
                if let Err(error) = visit(entry) {
                    stream_error = Some(error);
                }
            }
            Ok(Ok(None)) => {
                listing_done = true;
                last_progress = Instant::now();
            }
            Ok(Err(error)) => stream_error = Some(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
                    operation: OPERATION,
                    message: "tree listing reader disconnected".to_owned(),
                }));
            }
        }
    }
    while listing_done && stream_error.is_none() && (status.is_none() || stderr.is_none()) {
        if stderr.is_none() {
            match poll_reader(&stderr_rx, OPERATION) {
                Ok(value) => stderr = value,
                Err(error) => stream_error = Some(error.into()),
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(error) => {
                    stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
                        operation: OPERATION,
                        message: error.to_string(),
                    }));
                }
            }
        }
        let failure = if overflow.load(Ordering::Acquire) {
            Some("bounded stderr exceeded")
        } else if last_progress.elapsed() >= timeout {
            Some("operation timed out")
        } else {
            None
        };
        if let Some(message) = failure {
            stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
                operation: OPERATION,
                message: message.to_owned(),
            }));
        }
        if (status.is_none() || stderr.is_none()) && stream_error.is_none() {
            thread::sleep(Duration::from_millis(5));
        }
    }
    if stream_error.is_some() {
        terminate_process_group(pid, &mut child, status.is_none());
    }
    drop(entry_rx);
    if listing_reader.join().is_err() && stream_error.is_none() {
        stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
            operation: OPERATION,
            message: "tree listing reader panicked".to_owned(),
        }));
    }
    if stderr_reader.join().is_err() && stream_error.is_none() {
        stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
            operation: OPERATION,
            message: "stderr reader panicked".to_owned(),
        }));
    }
    let stderr = if let Some(bytes) = stderr {
        bytes
    } else {
        match stderr_rx.recv() {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => {
                if stream_error.is_none() {
                    stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
                        operation: OPERATION,
                        message: error.to_string(),
                    }));
                }
                Vec::new()
            }
            Err(_) => {
                if stream_error.is_none() {
                    stream_error = Some(super::GitAdmissionError::Git(GitCommandError {
                        operation: OPERATION,
                        message: "stderr reader disconnected".to_owned(),
                    }));
                }
                Vec::new()
            }
        }
    };
    if let Some(error) = stream_error {
        return Err(error);
    }
    let status = status.expect("successful listing records a child status");
    if !status.success() {
        return Err(super::GitAdmissionError::Git(GitCommandError {
            operation: OPERATION,
            message: format!(
                "process exited with {status}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        }));
    }
    Ok(())
}

fn tree_files(
    _store: &Store,
    runner: &GitRunner<'_>,
    git_dir: &Directory,
    format: GitObjectFormat,
    oid: &GitOid,
) -> Result<Vec<RawFile>, super::GitAdmissionError> {
    if oid.format() != format {
        return Err(super::GitAdmissionError::CheckpointObjectFormatMismatch);
    }
    let cat_file = runner.command(
        git_dir,
        &repository_args(vec![OsString::from("cat-file"), OsString::from("--batch")]),
    );
    let mut blobs = CatFileBatch::spawn(cat_file, runner.timeout)?;
    let command = runner.command(
        git_dir,
        &repository_args(vec![
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            OsString::from(oid.as_hex()),
        ]),
    );
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    stream_tree_listing(command, format, runner.timeout, |entry| {
        let file_limit = canonical_blob_limit(entry.class)
            .ok_or(super::GitAdmissionError::NonCanonicalTrackedPath)?;
        let bytes = blobs.read_blob(&entry.blob, file_limit)?;
        total_bytes = total_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| GitCommandError {
                operation: "read canonical blob",
                message: "canonical byte count overflow".to_owned(),
            })?)
            .ok_or_else(|| GitCommandError {
                operation: "read canonical blob",
                message: "canonical byte count overflow".to_owned(),
            })?;
        if total_bytes > MAX_TOTAL_CANONICAL_BYTES {
            return Err(super::GitAdmissionError::Git(GitCommandError {
                operation: "read canonical blob",
                message: "canonical aggregate byte limit exceeded".to_owned(),
            }));
        }
        files.push(RawFile {
            path: entry.path,
            bytes,
        });
        Ok(())
    })?;
    blobs.finish()?;
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::{
        CatFileBatch, TreeDiffCursor, TreeListingCursor, audit_repository_metadata,
        clear_cat_file_response_send_hook, count_reachable_inventory,
        immutable_edge_violation_from_reader, install_cat_file_response_send_hook,
        read_cat_file_response, run_bounded_command, run_bounded_command_to_file,
        stream_tree_listing,
    };
    use std::{
        io::{BufReader, Cursor, Read},
        process::Command,
        sync::{Arc, Barrier},
        thread,
        time::{Duration, Instant},
    };

    struct ChunkedReader {
        inner: Cursor<Vec<u8>>,
        max_chunk: usize,
    }
    impl Read for ChunkedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let length = buffer.len().min(self.max_chunk);
            self.inner.read(&mut buffer[..length])
        }
    }

    #[test]
    fn tree_listing_cursor_streams_nul_records_across_read_boundaries() {
        let oid_a = "1111111111111111111111111111111111111111";
        let oid_b = "2222222222222222222222222222222222222222";
        let path_a = "batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";
        let path_b =
            "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json";
        let listing = format!(
            "100644 blob {oid_a}\t{path_a}\0\
             100644 blob {oid_b}\t{path_b}\0"
        )
        .into_bytes();
        let reader = BufReader::with_capacity(
            2,
            ChunkedReader {
                inner: Cursor::new(listing),
                max_chunk: 3,
            },
        );
        let mut cursor = TreeListingCursor::new(reader, crate::GitObjectFormat::Sha1);

        let first = cursor.next_entry().expect("first record").expect("first");
        assert_eq!(first.path, path_a.as_bytes());
        assert_eq!(first.blob.as_hex(), oid_a);
        assert_eq!(first.class, crate::PathClass::LegacyBatch);
        let second = cursor.next_entry().expect("second record").expect("second");
        assert_eq!(second.path, path_b.as_bytes());
        assert_eq!(second.blob.as_hex(), oid_b);
        assert_eq!(second.class, crate::PathClass::LegacyEvent);
        assert!(cursor.next_entry().expect("end").is_none());
    }

    #[test]
    fn tree_listing_entry_budget_counts_canonical_parents() {
        let oid = "1111111111111111111111111111111111111111";
        let first = "journal/records/example.notes/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json";
        let second = "journal/records/example.notes/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174002.json";
        let listing = format!(
            "100644 blob {oid}\t{first}\0\
             100644 blob {oid}\t{second}\0"
        );
        let mut cursor = TreeListingCursor::new(
            BufReader::new(Cursor::new(listing.into_bytes())),
            crate::GitObjectFormat::Sha1,
        );
        // The first path contributes the file and its three non-root canonical parents;
        // the second path contributes one more file.
        cursor.entry_budget = crate::store::CanonicalEntryBudget::with_entries(
            crate::store::MAX_CANONICAL_ENTRIES - 4,
        );
        assert!(cursor.next_entry().expect("exact-limit entry").is_some());
        let Err(error) = cursor.next_entry() else {
            panic!("limit plus one canonical entry must fail");
        };
        assert!(error.to_string().contains("entry-count limit"));
    }

    #[test]
    fn tree_diff_cursor_streams_additions_across_read_boundaries() {
        let oid_a = "1111111111111111111111111111111111111111";
        let oid_b = "2222222222222222222222222222222222222222";
        let path_a = "batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";
        let path_b =
            "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json";
        let zeros = "0000000000000000000000000000000000000000";
        let diff = format!(
            ":000000 100644 {zeros} {oid_a} A\0{path_a}\0\
             :000000 100644 {zeros} {oid_b} A\0{path_b}\0"
        )
        .into_bytes();
        let reader = BufReader::with_capacity(
            2,
            ChunkedReader {
                inner: Cursor::new(diff),
                max_chunk: 3,
            },
        );
        let mut cursor = TreeDiffCursor::new(reader, crate::GitObjectFormat::Sha1);

        let first = cursor
            .next_addition()
            .expect("first record")
            .expect("first");
        assert_eq!(first.path, path_a.as_bytes());
        assert_eq!(first.blob.as_hex(), oid_a);
        assert_eq!(first.class, crate::PathClass::LegacyBatch);
        let second = cursor
            .next_addition()
            .expect("second record")
            .expect("second");
        assert_eq!(second.path, path_b.as_bytes());
        assert_eq!(second.blob.as_hex(), oid_b);
        assert_eq!(second.class, crate::PathClass::LegacyEvent);
        assert!(cursor.next_addition().expect("end").is_none());
    }

    #[test]
    fn tree_diff_cursor_rejects_non_additions_and_malformed_streams() {
        let oid = "1111111111111111111111111111111111111111";
        let zeros = "0000000000000000000000000000000000000000";
        let path = "batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";
        let hostiles = [
            format!(":100644 100644 {oid} {oid} M\0{path}\0"),
            format!(":000000 100755 {zeros} {oid} A\0{path}\0"),
            format!(":000000 100644 {oid} {oid} A\0{path}\0"),
            format!(":000000 100644 {zeros} {oid} D\0{path}\0"),
            format!(":000000 100644 {zeros} short A\0{path}\0"),
            format!(":000000 100644 {zeros} {oid} A\0{path}"),
        ];
        for hostile in hostiles {
            let mut cursor = TreeDiffCursor::new(
                BufReader::new(Cursor::new(hostile.into_bytes())),
                crate::GitObjectFormat::Sha1,
            );
            assert!(cursor.next_addition().is_err());
        }

        let later =
            "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174002.json";
        let earlier = "batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";
        let unordered = format!(
            ":000000 100644 {zeros} {oid} A\0{later}\0\
             :000000 100644 {zeros} {oid} A\0{earlier}\0"
        );
        let mut cursor = TreeDiffCursor::new(
            BufReader::new(Cursor::new(unordered.into_bytes())),
            crate::GitObjectFormat::Sha1,
        );
        assert!(cursor.next_addition().expect("first").is_some());
        assert!(cursor.next_addition().is_err());
    }

    #[test]
    fn reachable_object_inventory_counts_across_read_boundaries_and_rejects_limit_plus_one() {
        let inventory = b"1111111111111111111111111111111111111111 first/path\n2222222222222222222222222222222222222222\n".to_vec();
        let reader = BufReader::with_capacity(
            2,
            ChunkedReader {
                inner: Cursor::new(inventory.clone()),
                max_chunk: 3,
            },
        );
        assert_eq!(
            count_reachable_inventory(reader, 2).expect("exact limit"),
            2
        );
        let reader = BufReader::with_capacity(
            2,
            ChunkedReader {
                inner: Cursor::new(inventory),
                max_chunk: 3,
            },
        );
        let error = count_reachable_inventory(reader, 1).expect_err("limit plus one");
        assert!(error.to_string().contains("object count exceeds bound"));
    }

    #[test]
    fn immutable_edge_stream_rejects_delete_and_modify_without_collecting_output() {
        for (status, expected) in [
            ("D", super::super::GitQuarantineReason::Deletion),
            ("M", super::super::GitQuarantineReason::Modification),
        ] {
            let output = format!("A\0first/path\0{status}\0second/path\0").into_bytes();
            let reader = BufReader::with_capacity(
                2,
                ChunkedReader {
                    inner: Cursor::new(output),
                    max_chunk: 3,
                },
            );
            assert_eq!(
                immutable_edge_violation_from_reader(reader).expect("parse diff"),
                Some(expected)
            );
        }
    }

    #[test]
    fn cat_file_response_streams_exact_framed_blob_across_read_boundaries() {
        let oid = "1111111111111111111111111111111111111111";
        let response = format!("{oid} blob 5\nhello\n").into_bytes();
        let mut reader = BufReader::with_capacity(
            2,
            ChunkedReader {
                inner: Cursor::new(response),
                max_chunk: 3,
            },
        );
        let expected = super::GitOid::parse(crate::GitObjectFormat::Sha1, oid).expect("OID");

        assert_eq!(
            read_cat_file_response(&mut reader, &expected, 5).expect("response"),
            b"hello"
        );
    }

    #[test]
    fn cat_file_batch_reuses_one_process_for_multiple_blobs() {
        let oid_a = "1111111111111111111111111111111111111111";
        let oid_b = "2222222222222222222222222222222222222222";
        let script = format!(
            r#"while IFS= read -r oid; do
  case "$oid" in
    "{oid_a}") printf '%s blob 3\none\n' "$oid" ;;
    "{oid_b}") printf '%s blob 3\ntwo\n' "$oid" ;;
    *) printf '%s missing\n' "$oid" ;;
  esac
done"#
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        let expected_a = super::GitOid::parse(crate::GitObjectFormat::Sha1, oid_a).expect("OID A");
        let expected_b = super::GitOid::parse(crate::GitObjectFormat::Sha1, oid_b).expect("OID B");
        let mut batch = CatFileBatch::spawn(command, Duration::from_secs(2)).expect("batch");

        assert_eq!(batch.read_blob(&expected_a, 3).expect("first"), b"one");
        assert_eq!(batch.read_blob(&expected_b, 3).expect("second"), b"two");
        batch.finish().expect("finish");
    }

    #[test]
    fn cat_file_batch_accepts_a_queued_response_after_direct_child_exit() {
        let oid = "3333333333333333333333333333333333333333";
        let script = "IFS= read -r oid; printf '%s blob 3\\none\\n' \"$oid\"";
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        let expected = super::GitOid::parse(crate::GitObjectFormat::Sha1, oid).expect("OID");
        let barrier = Arc::new(Barrier::new(2));
        install_cat_file_response_send_hook(&expected, Arc::clone(&barrier));
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            barrier.wait();
        });
        let mut batch = CatFileBatch::spawn(command, Duration::from_secs(2)).expect("batch");

        let response = batch.read_blob(&expected, 3);

        releaser.join().expect("release hook");
        clear_cat_file_response_send_hook();
        assert_eq!(response.expect("queued response"), b"one");
        batch.finish().expect("finish");
    }

    #[test]
    fn cat_file_batch_finish_times_out_when_descendant_holds_stderr() {
        let oid = "1111111111111111111111111111111111111111";
        let script = r#"IFS= read -r oid
printf '%s blob 3\none\n' "$oid"
sleep 0.05
sleep 3 >/dev/null &"#;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        let expected = super::GitOid::parse(crate::GitObjectFormat::Sha1, oid).expect("OID");
        let mut batch = CatFileBatch::spawn(command, Duration::from_millis(100)).expect("batch");
        assert_eq!(batch.read_blob(&expected, 3).expect("blob"), b"one");
        let started = Instant::now();

        let error = batch.finish().expect_err("held stderr must time out");

        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn tree_listing_process_streams_records_from_a_live_pipe() {
        let oid_a = "1111111111111111111111111111111111111111";
        let oid_b = "2222222222222222222222222222222222222222";
        let path_a = "batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";
        let path_b =
            "events/123e4567-e89b-42d3-a456-426614174000/01913f1d-8e2a-7c30-8f4a-426614174001.json";
        let script = format!(
            "printf '%s\\0%s\\0' '100644 blob {oid_a}\t{path_a}' \
             '100644 blob {oid_b}\t{path_b}'"
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        let mut paths = Vec::new();

        stream_tree_listing(
            command,
            crate::GitObjectFormat::Sha1,
            Duration::from_secs(2),
            |entry| {
                paths.push(entry.path);
                Ok(())
            },
        )
        .expect("stream listing");

        assert_eq!(paths, [path_a.as_bytes(), path_b.as_bytes()]);
    }

    #[test]
    fn tree_listing_process_times_out_when_descendant_holds_stderr() {
        let oid = "1111111111111111111111111111111111111111";
        let path = "batches/01913f1d-8e2a-7c30-8f4a-426614174012.json";
        let script = format!(
            "printf '%s\\0' '100644 blob {oid}\t{path}'; \
             sleep 0.05; sleep 3 >/dev/null &"
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        let started = Instant::now();

        let error = stream_tree_listing(
            command,
            crate::GitObjectFormat::Sha1,
            Duration::from_millis(100),
            |_| Ok(()),
        )
        .expect_err("held stderr must time out");

        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn hostile_git_authority_is_inert() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-hostile-git-audit-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(root.join("objects/info")).expect("objects info");
        std::fs::create_dir_all(root.join("refs/replace")).expect("replace refs");
        std::fs::write(root.join("objects/info/alternates"), b"/hostile\n").expect("alternates");
        let directory = crate::store::Directory::open_ambient(&root).expect("directory");
        let error = audit_repository_metadata(&directory).expect_err("reject alternates");
        assert_eq!(error.operation(), "audit repository metadata");
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_process_runner_spools_stdout_to_a_file() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-bounded-output-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("output");
        let output = std::fs::File::create(&path).expect("output file");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf streamed-output"]);

        let bytes = run_bounded_command_to_file(
            command,
            "test file output",
            output,
            64,
            64,
            Duration::from_secs(2),
        )
        .expect("bounded file output");

        assert_eq!(bytes, 15);
        assert_eq!(
            std::fs::read(&path).expect("read output"),
            b"streamed-output"
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_process_file_writer_stops_at_its_limit() {
        let root = std::env::temp_dir().join(format!(
            "wayjournal-bounded-output-limit-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("output");
        let output = std::fs::File::create(&path).expect("output file");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do printf xxxxxxxxxxxxxxxx; done"]);
        let started = Instant::now();

        let error = run_bounded_command_to_file(
            command,
            "test bounded file output",
            output,
            1024,
            64,
            Duration::from_secs(2),
        )
        .expect_err("unbounded output must fail");

        assert!(error.to_string().contains("bounded output exceeded"));
        assert!(std::fs::metadata(&path).expect("metadata").len() <= 1024);
        assert!(started.elapsed() < Duration::from_secs(2));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn bounded_process_runner_times_out_and_reaps_its_process_group() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & wait"]);
        let started = Instant::now();
        let error = run_bounded_command(
            command,
            "timeout probe",
            1024,
            1024,
            Duration::from_millis(100),
        )
        .expect_err("timeout");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bounded_process_runner_kills_descendants_that_hold_pipes_after_parent_exit() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 &"]);
        let started = Instant::now();
        let error = run_bounded_command(
            command,
            "descendant timeout probe",
            1024,
            1024,
            Duration::from_millis(100),
        )
        .expect_err("descendant timeout");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bounded_process_runner_stops_before_accumulating_unbounded_output() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "while :; do printf 0123456789abcdef; done"]);
        let started = Instant::now();
        let error =
            run_bounded_command(command, "output probe", 1024, 1024, Duration::from_secs(2))
                .expect_err("output bound");
        assert!(error.to_string().contains("bounded output exceeded"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
