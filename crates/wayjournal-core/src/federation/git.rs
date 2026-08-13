use std::{
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    os::unix::process::CommandExt,
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
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "never")
            .env("GIT_ASKPASS", "/bin/false")
            .env("SSH_ASKPASS", "/bin/false")
            .env("GIT_SSH_COMMAND", "/bin/false")
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
        let command = self.command(cwd, args);
        let captured = run_bounded_command(
            command,
            operation,
            stdout_limit,
            MAX_SMALL_OUTPUT,
            self.timeout,
        )?;
        if captured.status.success() {
            return Ok(captured.stdout);
        }
        drop(captured.stderr);
        Err(GitCommandError {
            operation,
            message: match captured.status.code() {
                Some(code) => format!("command exited with status {code}"),
                None => "command terminated by signal".to_owned(),
            },
        })
    }
}

#[derive(Debug)]
struct CapturedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[allow(clippy::too_many_lines)]
#[allow(unsafe_code)]
fn run_bounded_command(
    mut command: Command,
    operation: &'static str,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
) -> Result<CapturedOutput, GitCommandError> {
    command
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
    scan_collected(store, &files, Vec::new()).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::run_bounded_command;
    use std::{
        process::Command,
        time::{Duration, Instant},
    };

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
