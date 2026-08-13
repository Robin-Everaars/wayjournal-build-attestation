use std::{
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        process::CommandExt,
    },
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
    MAX_BATCH_BYTES, MAX_RECORD_BYTES, PathClass, Store, classify_path,
    store::{Directory, MAX_CANONICAL_ENTRIES, MAX_TOTAL_CANONICAL_BYTES, RawFile, scan_collected},
};

use super::{GitObjectFormat, GitOid, GitSyncRequest};

const MAX_SMALL_OUTPUT: usize = 64 * 1024;
const MAX_TREE_OUTPUT: usize = 512 * 1024 * 1024;
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
        let output = runner.output(
            "validate immutable history edge",
            &self.bare,
            &repository_args(vec![
                OsString::from("diff-tree"),
                OsString::from("-r"),
                OsString::from("--no-commit-id"),
                OsString::from("--name-status"),
                OsString::from("-z"),
                OsString::from(parent.as_hex()),
                OsString::from(child.as_hex()),
                OsString::from("--"),
            ]),
            MAX_TREE_OUTPUT,
        )?;
        for entry in output
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            if entry.first() == Some(&b'D') {
                return Ok(Some(super::GitQuarantineReason::Deletion));
            }
            if entry.first() == Some(&b'M') {
                return Ok(Some(super::GitQuarantineReason::Modification));
            }
        }
        Ok(None)
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

    pub(super) fn tree_files(
        &self,
        store: &Store,
        runner: &GitRunner<'_>,
        oid: &GitOid,
    ) -> Result<Vec<RawFile>, super::GitAdmissionError> {
        tree_files(store, runner, &self.bare, self.format, oid)
    }

    pub(super) fn tree_snapshot(
        &self,
        store: &Store,
        runner: &GitRunner<'_>,
        oid: &GitOid,
    ) -> Result<crate::StoreSnapshot, super::GitAdmissionError> {
        tree_snapshot(store, runner, &self.bare, self.format, oid)
    }

    pub(super) fn tree_paths(
        &self,
        runner: &GitRunner<'_>,
        oid: &GitOid,
    ) -> Result<std::collections::BTreeSet<Vec<u8>>, super::GitAdmissionError> {
        tree_paths(runner, &self.bare, self.format, oid)
    }

    pub(super) fn path_exists(
        &self,
        runner: &GitRunner<'_>,
        oid: &GitOid,
        path: &[u8],
    ) -> Result<bool, GitCommandError> {
        let mut spec = oid.as_hex().as_bytes().to_vec();
        spec.push(b':');
        spec.extend_from_slice(path);
        runner.succeeds(
            "test canonical path in tree",
            &self.bare,
            &repository_args(vec![
                OsString::from("cat-file"),
                OsString::from("-e"),
                OsString::from_vec(spec),
            ]),
        )
    }

    pub(super) fn path_bytes(
        &self,
        runner: &GitRunner<'_>,
        oid: &GitOid,
        path: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, GitCommandError> {
        let mut spec = oid.as_hex().as_bytes().to_vec();
        spec.push(b':');
        spec.extend_from_slice(path);
        runner.output(
            "read canonical path from tree",
            &self.bare,
            &repository_args(vec![
                OsString::from("cat-file"),
                OsString::from("blob"),
                OsString::from_vec(spec),
            ]),
            limit,
        )
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
    let objects = runner.output(
        "inventory fetched objects",
        &repository.bare,
        &repository_args(args(&["rev-list", "--objects", "--all"])),
        MAX_TREE_OUTPUT,
    )?;
    let count = objects
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count();
    if count > MAX_PENDING_REPO_OBJECTS {
        return Err(GitCommandError {
            operation: "inventory fetched objects",
            message: "reachable object count exceeds bound".to_owned(),
        });
    }
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

fn tree_paths(
    runner: &GitRunner<'_>,
    git_dir: &Directory,
    format: GitObjectFormat,
    oid: &GitOid,
) -> Result<std::collections::BTreeSet<Vec<u8>>, super::GitAdmissionError> {
    if oid.format() != format {
        return Err(super::GitAdmissionError::CheckpointObjectFormatMismatch);
    }
    let listing = runner.output(
        "list canonical tree paths",
        git_dir,
        &repository_args(vec![
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-z"),
            OsString::from("--name-only"),
            OsString::from("--full-tree"),
            OsString::from(oid.as_hex()),
        ]),
        MAX_TREE_OUTPUT,
    )?;
    let mut paths = std::collections::BTreeSet::new();
    for path in listing
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        if paths.len() >= MAX_CANONICAL_ENTRIES {
            return Err(super::GitAdmissionError::Git(GitCommandError {
                operation: "parse tree paths",
                message: "canonical entry-count limit exceeded".to_owned(),
            }));
        }
        if !matches!(
            classify_path(path),
            PathClass::LegacyEvent
                | PathClass::LegacyBatch
                | PathClass::JournalRecord
                | PathClass::JournalBatch
        ) || !paths.insert(path.to_vec())
        {
            return Err(super::GitAdmissionError::NonCanonicalTrackedPath);
        }
    }
    Ok(paths)
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
    let listing = runner.output(
        "list canonical tree",
        git_dir,
        &repository_args(vec![
            OsString::from("ls-tree"),
            OsString::from("-r"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            OsString::from(oid.as_hex()),
        ]),
        MAX_TREE_OUTPUT,
    )?;
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for entry in listing
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        if files.len() >= MAX_CANONICAL_ENTRIES {
            return Err(super::GitAdmissionError::Git(GitCommandError {
                operation: "parse tree",
                message: "canonical entry-count limit exceeded".to_owned(),
            }));
        }
        let separator = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| GitCommandError {
                operation: "parse tree",
                message: "tree entry has no path separator".to_owned(),
            })?;
        let (metadata, path_with_tab) = entry.split_at(separator);
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
        let blob = std::str::from_utf8(blob).map_err(|_| GitCommandError {
            operation: "parse tree",
            message: "blob id is not UTF-8".to_owned(),
        })?;
        GitOid::parse(format, blob).map_err(|error| GitCommandError {
            operation: "parse tree",
            message: error.to_string(),
        })?;
        let file_limit = match class {
            PathClass::JournalRecord => MAX_RECORD_BYTES,
            PathClass::JournalBatch => MAX_BATCH_BYTES,
            PathClass::LegacyEvent | PathClass::LegacyBatch => crate::MAX_LEGACY_FILE_BYTES,
            PathClass::NonCanonical | PathClass::InvalidReserved => unreachable!(),
        };
        let bytes = runner.output(
            "read canonical blob",
            git_dir,
            &repository_args(vec![
                OsString::from("cat-file"),
                OsString::from("blob"),
                OsString::from(blob),
            ]),
            file_limit,
        )?;
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
            path: path.to_vec(),
            bytes,
        });
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::{audit_repository_metadata, run_bounded_command};
    use std::{
        process::Command,
        time::{Duration, Instant},
    };

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
