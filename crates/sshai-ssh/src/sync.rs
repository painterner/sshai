//! Two-way directory synchronization in the shape of Mutagen's safe mode: both
//! endpoints are scanned, the last agreed state is remembered as an ancestor,
//! and a three-way comparison only touches a side when the *other* side is the
//! one that changed. Where both sides changed the path is a conflict, which the
//! default policy reports instead of guessing.
//!
//! Content identity is a BLAKE3 digest. Remote digests are computed by the
//! remote worker, so scanning never moves file contents; only the files that
//! actually need to be copied are transferred, over SFTP.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{Result, SshError};

/// Bumped when a stored state file can no longer be understood.
pub const SYNC_STATE_VERSION: u32 = 1;

/// Guard against synchronizing a tree that is far larger than intended.
pub const MAX_SYNC_ENTRIES: usize = 200_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
}

/// One path as a scan observed it, with the digest resolved for files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub kind: EntryKind,
    pub size: u64,
    pub modified_ms: Option<u64>,
    pub executable: bool,
    pub digest: Option<String>,
}

impl Entry {
    pub fn directory() -> Self {
        Self {
            kind: EntryKind::Directory,
            size: 0,
            modified_ms: None,
            executable: false,
            digest: None,
        }
    }

    pub fn file(size: u64, modified_ms: Option<u64>, executable: bool, digest: &str) -> Self {
        Self {
            kind: EntryKind::File,
            size,
            modified_ms,
            executable,
            digest: Some(digest.to_owned()),
        }
    }

    fn same_content(&self, other: &Self) -> bool {
        if self.kind != other.kind {
            return false;
        }
        match self.kind {
            EntryKind::Directory => true,
            EntryKind::File => {
                self.executable == other.executable
                    && match (self.digest.as_deref(), other.digest.as_deref()) {
                        (Some(left), Some(right)) => left == right,
                        // A file whose digest is unknown is never assumed equal.
                        _ => false,
                    }
            }
        }
    }
}

/// Relative paths, `/`-separated, without a leading slash.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub entries: BTreeMap<String, Entry>,
    /// Directories that hold at least one ignored child, which is content this
    /// pair never synchronized and must never remove.
    pub ignored_parents: BTreeSet<String>,
}

impl Snapshot {
    pub fn insert(&mut self, path: impl Into<String>, entry: Entry) {
        self.entries.insert(path.into(), entry);
    }
}

/// The last state both sides agreed on, which is what makes a change on one
/// side distinguishable from a change on the other.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AncestorEntry {
    pub kind: EntryKind,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default)]
    pub executable: bool,
}

impl AncestorEntry {
    fn from_entry(entry: &Entry) -> Self {
        Self {
            kind: entry.kind,
            size: entry.size,
            digest: entry.digest.clone(),
            executable: entry.executable,
        }
    }

    fn matches(&self, entry: &Entry) -> bool {
        if self.kind != entry.kind {
            return false;
        }
        match self.kind {
            EntryKind::Directory => true,
            EntryKind::File => {
                self.executable == entry.executable
                    && match (self.digest.as_deref(), entry.digest.as_deref()) {
                        (Some(left), Some(right)) => left == right,
                        _ => false,
                    }
            }
        }
    }
}

/// A digest remembered under the metadata a scan sees for free, so an unchanged
/// file is never hashed twice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CachedDigest {
    pub size: u64,
    #[serde(default)]
    pub modified_ms: Option<u64>,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncState {
    pub version: u32,
    #[serde(default)]
    pub ancestor: BTreeMap<String, AncestorEntry>,
    #[serde(default)]
    pub local_cache: BTreeMap<String, CachedDigest>,
    #[serde(default)]
    pub remote_cache: BTreeMap<String, CachedDigest>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            version: SYNC_STATE_VERSION,
            ancestor: BTreeMap::new(),
            local_cache: BTreeMap::new(),
            remote_cache: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConflictPolicy {
    /// Report the conflict and change neither side.
    #[default]
    Safe,
    /// The local side wins.
    Local,
    /// The remote side wins.
    Remote,
    /// The more recently modified side wins; without usable timestamps this
    /// stays a conflict.
    Newest,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Side {
    Local,
    Remote,
}

impl Side {
    pub fn other(self) -> Self {
        match self {
            Self::Local => Self::Remote,
            Self::Remote => Self::Local,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    CreateDirectory {
        side: Side,
        path: String,
    },
    CopyFile {
        to: Side,
        path: String,
    },
    Delete {
        side: Side,
        path: String,
        directory: bool,
    },
}

impl Action {
    pub fn path(&self) -> &str {
        match self {
            Self::CreateDirectory { path, .. }
            | Self::CopyFile { path, .. }
            | Self::Delete { path, .. } => path,
        }
    }

    pub fn side(&self) -> Side {
        match self {
            Self::CreateDirectory { side, .. } | Self::Delete { side, .. } => *side,
            Self::CopyFile { to, .. } => *to,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictReason {
    /// Both sides changed the contents.
    BothChanged,
    /// One side deleted the path while the other changed it.
    DeletedAndChanged { deleted: Side },
    /// A file on one side and a directory on the other.
    KindMismatch,
    /// A directory was deleted on one side while the other side still has
    /// content inside it that is not being removed.
    DirectoryHasChanges { deleted: Side },
    /// A directory was deleted on one side while the other side still holds
    /// ignored content inside it.
    DirectoryHoldsIgnored { deleted: Side },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conflict {
    pub path: String,
    pub reason: ConflictReason,
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub actions: Vec<Action>,
    pub conflicts: Vec<Conflict>,
    /// Deletions that `--no-delete` held back.
    pub withheld_deletes: Vec<(Side, String)>,
    pub unchanged: usize,
    /// The ancestor to store if every action succeeds.
    pub ancestor: BTreeMap<String, AncestorEntry>,
}

#[derive(Clone, Copy, Debug)]
pub struct ReconcileOptions {
    pub policy: ConflictPolicy,
    pub propagate_deletes: bool,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self {
            policy: ConflictPolicy::default(),
            propagate_deletes: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Change {
    /// Absent from the ancestor and from this side.
    Absent,
    Unchanged,
    Created,
    Modified,
    Deleted,
}

impl Change {
    fn changed(self) -> bool {
        matches!(self, Self::Created | Self::Modified)
    }
}

fn classify(ancestor: Option<&AncestorEntry>, current: Option<&Entry>) -> Change {
    match (ancestor, current) {
        (None, None) => Change::Absent,
        (None, Some(_)) => Change::Created,
        (Some(_), None) => Change::Deleted,
        (Some(ancestor), Some(current)) => {
            if ancestor.matches(current) {
                Change::Unchanged
            } else {
                Change::Modified
            }
        }
    }
}

/// Decide what to do with every path, without touching either filesystem.
pub fn reconcile(
    ancestor: &BTreeMap<String, AncestorEntry>,
    local: &Snapshot,
    remote: &Snapshot,
    options: ReconcileOptions,
) -> Plan {
    let mut plan = Plan::default();
    let paths = ancestor
        .keys()
        .chain(local.entries.keys())
        .chain(remote.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    for path in paths {
        let previous = ancestor.get(&path);
        let local_entry = local.entries.get(&path);
        let remote_entry = remote.entries.get(&path);
        let local_change = classify(previous, local_entry);
        let remote_change = classify(previous, remote_entry);

        match (local_change, remote_change) {
            (Change::Absent, Change::Absent) => {}
            (Change::Unchanged, Change::Unchanged) => {
                plan.unchanged += 1;
                if let Some(entry) = local_entry {
                    plan.ancestor.insert(path, AncestorEntry::from_entry(entry));
                }
            }
            (Change::Deleted, Change::Deleted) => {}
            (local_state, remote_state) if local_state.changed() && remote_state.changed() => {
                match (local_entry, remote_entry) {
                    (Some(left), Some(right)) if left.same_content(right) => {
                        // Both sides arrived at the same content on their own.
                        plan.unchanged += 1;
                        plan.ancestor.insert(path, AncestorEntry::from_entry(left));
                    }
                    (Some(left), Some(right)) => {
                        resolve_conflict(&mut plan, &path, left, right, previous, options);
                    }
                    _ => {}
                }
            }
            (Change::Deleted, remote_state) if remote_state.changed() => {
                resolve_delete_conflict(
                    &mut plan,
                    &path,
                    Side::Local,
                    remote_entry,
                    local_entry,
                    previous,
                    options,
                );
            }
            (local_state, Change::Deleted) if local_state.changed() => {
                resolve_delete_conflict(
                    &mut plan,
                    &path,
                    Side::Remote,
                    local_entry,
                    remote_entry,
                    previous,
                    options,
                );
            }
            (local_state, _) if local_state.changed() => {
                propagate(
                    &mut plan,
                    &path,
                    Side::Remote,
                    local_entry,
                    remote_entry,
                    options,
                );
            }
            (_, remote_state) if remote_state.changed() => {
                propagate(
                    &mut plan,
                    &path,
                    Side::Local,
                    remote_entry,
                    local_entry,
                    options,
                );
            }
            (Change::Deleted, _) => {
                delete(
                    &mut plan,
                    &path,
                    Side::Remote,
                    remote_entry,
                    previous,
                    options,
                );
            }
            (_, Change::Deleted) => {
                delete(
                    &mut plan,
                    &path,
                    Side::Local,
                    local_entry,
                    previous,
                    options,
                );
            }
            _ => {}
        }
    }

    guard_directory_deletes(&mut plan, ancestor, local, remote);
    sort_actions(&mut plan.actions);
    plan
}

/// Removing a directory must not take anything with it that the other side
/// still wants. Where it would, the directory stays and the path is a conflict.
fn guard_directory_deletes(
    plan: &mut Plan,
    ancestor: &BTreeMap<String, AncestorEntry>,
    local: &Snapshot,
    remote: &Snapshot,
) {
    let deleted_paths = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::Delete { side, path, .. } => Some((*side, path.clone())),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut directories = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::Delete {
                side,
                path,
                directory: true,
            } => Some((*side, path.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    // Shallowest first, so cancelling a parent also cancels what is under it.
    directories.sort_by_key(|(_, path)| depth(path));

    let mut cancelled: Vec<(Side, String)> = Vec::new();
    for (side, path) in directories {
        if cancelled
            .iter()
            .any(|(other, parent)| *other == side && is_inside(&path, parent))
        {
            cancelled.push((side, path));
            continue;
        }
        let destination = match side {
            Side::Local => local,
            Side::Remote => remote,
        };
        let holds_ignored = destination
            .ignored_parents
            .iter()
            .any(|parent| *parent == path || is_inside(parent, &path));
        let keeps_content = destination
            .entries
            .keys()
            .filter(|candidate| is_inside(candidate, &path))
            .any(|candidate| !deleted_paths.contains(&(side, candidate.clone())));
        if holds_ignored || keeps_content {
            plan.conflicts.push(Conflict {
                path: path.clone(),
                reason: if keeps_content {
                    ConflictReason::DirectoryHasChanges {
                        deleted: side.other(),
                    }
                } else {
                    ConflictReason::DirectoryHoldsIgnored {
                        deleted: side.other(),
                    }
                },
            });
            cancelled.push((side, path));
        }
    }

    if cancelled.is_empty() {
        return;
    }
    // Only the directory itself stays. Files inside it that the other side
    // removed are still ordinary deletions.
    plan.actions.retain(|action| match action {
        Action::Delete {
            side,
            path,
            directory: true,
        } => !cancelled
            .iter()
            .any(|(other, cancelled)| other == side && cancelled == path),
        _ => true,
    });
    for (_, path) in &cancelled {
        if let Some(entry) = ancestor.get(path) {
            plan.ancestor.insert(path.clone(), entry.clone());
        }
    }
}

/// Whether `path` lies under `parent`.
fn is_inside(path: &str, parent: &str) -> bool {
    parent.is_empty() || path.starts_with(&format!("{parent}/"))
}

/// Copy `source` onto `target_side`, deleting a destination of another kind
/// first. Replacing a directory with a file is a conflict unless a policy says
/// which side wins, because it would remove a whole subtree.
fn propagate(
    plan: &mut Plan,
    path: &str,
    target_side: Side,
    source: Option<&Entry>,
    destination: Option<&Entry>,
    options: ReconcileOptions,
) {
    let Some(source) = source else { return };
    if let Some(destination) = destination
        && destination.kind != source.kind
    {
        if destination.kind == EntryKind::Directory && options.policy == ConflictPolicy::Safe {
            plan.conflicts.push(Conflict {
                path: path.to_owned(),
                reason: ConflictReason::KindMismatch,
            });
            return;
        }
        plan.actions.push(Action::Delete {
            side: target_side,
            path: path.to_owned(),
            directory: destination.kind == EntryKind::Directory,
        });
    }
    match source.kind {
        EntryKind::Directory => plan.actions.push(Action::CreateDirectory {
            side: target_side,
            path: path.to_owned(),
        }),
        EntryKind::File => plan.actions.push(Action::CopyFile {
            to: target_side,
            path: path.to_owned(),
        }),
    }
    plan.ancestor
        .insert(path.to_owned(), AncestorEntry::from_entry(source));
}

fn delete(
    plan: &mut Plan,
    path: &str,
    target_side: Side,
    destination: Option<&Entry>,
    previous: Option<&AncestorEntry>,
    options: ReconcileOptions,
) {
    let Some(destination) = destination else {
        return;
    };
    if !options.propagate_deletes {
        plan.withheld_deletes.push((target_side, path.to_owned()));
        if let Some(previous) = previous {
            plan.ancestor.insert(path.to_owned(), previous.clone());
        }
        return;
    }
    plan.actions.push(Action::Delete {
        side: target_side,
        path: path.to_owned(),
        directory: destination.kind == EntryKind::Directory,
    });
}

fn resolve_conflict(
    plan: &mut Plan,
    path: &str,
    local: &Entry,
    remote: &Entry,
    previous: Option<&AncestorEntry>,
    options: ReconcileOptions,
) {
    let winner = match options.policy {
        ConflictPolicy::Safe => None,
        ConflictPolicy::Local => Some(Side::Local),
        ConflictPolicy::Remote => Some(Side::Remote),
        ConflictPolicy::Newest => match (local.modified_ms, remote.modified_ms) {
            (Some(left), Some(right)) if left != right => Some(if left > right {
                Side::Local
            } else {
                Side::Remote
            }),
            _ => None,
        },
    };
    let Some(winner) = winner else {
        plan.conflicts.push(Conflict {
            path: path.to_owned(),
            reason: if local.kind == remote.kind {
                ConflictReason::BothChanged
            } else {
                ConflictReason::KindMismatch
            },
        });
        keep_ancestor(plan, path, previous);
        return;
    };
    let (source, destination) = match winner {
        Side::Local => (local, remote),
        Side::Remote => (remote, local),
    };
    propagate(
        plan,
        path,
        winner.other(),
        Some(source),
        Some(destination),
        options,
    );
}

fn resolve_delete_conflict(
    plan: &mut Plan,
    path: &str,
    deleted: Side,
    changed_entry: Option<&Entry>,
    deleted_entry: Option<&Entry>,
    previous: Option<&AncestorEntry>,
    options: ReconcileOptions,
) {
    let winner = match options.policy {
        ConflictPolicy::Safe | ConflictPolicy::Newest => None,
        ConflictPolicy::Local => Some(Side::Local),
        ConflictPolicy::Remote => Some(Side::Remote),
    };
    match winner {
        // The side that deleted wins: delete on the other side too.
        Some(winner) if winner == deleted => {
            delete(
                plan,
                path,
                deleted.other(),
                changed_entry,
                previous,
                ReconcileOptions {
                    propagate_deletes: true,
                    ..options
                },
            );
        }
        // The side that changed wins: restore the path where it was deleted.
        Some(_) => propagate(plan, path, deleted, changed_entry, deleted_entry, options),
        None => {
            plan.conflicts.push(Conflict {
                path: path.to_owned(),
                reason: ConflictReason::DeletedAndChanged { deleted },
            });
            keep_ancestor(plan, path, previous);
        }
    }
}

fn keep_ancestor(plan: &mut Plan, path: &str, previous: Option<&AncestorEntry>) {
    if let Some(previous) = previous {
        plan.ancestor.insert(path.to_owned(), previous.clone());
    }
}

fn depth(path: &str) -> usize {
    path.split('/').count()
}

/// Deletions that clear the way for a replacement run first, deepest first, so
/// a directory is empty by the time it is removed. Then directories are created
/// parents first, then files are copied, and the remaining deletions run last,
/// again deepest first.
fn sort_actions(actions: &mut [Action]) {
    let replaced = actions
        .iter()
        .filter_map(|action| match action {
            Action::CreateDirectory { side, path } => Some((*side, path.clone())),
            Action::CopyFile { to, path } => Some((*to, path.clone())),
            Action::Delete { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let clears_the_way = |side: Side, path: &str| {
        replaced.iter().any(|(other, replaced)| {
            *other == side && (replaced == path || is_inside(path, replaced))
        })
    };
    let rank = |action: &Action| -> u8 {
        match action {
            Action::Delete { side, path, .. } if clears_the_way(*side, path) => 0,
            Action::CreateDirectory { .. } => 1,
            Action::CopyFile { .. } => 2,
            Action::Delete { .. } => 3,
        }
    };
    actions.sort_by(|left, right| {
        let (left_rank, right_rank) = (rank(left), rank(right));
        left_rank.cmp(&right_rank).then_with(|| {
            if matches!(left, Action::Delete { .. }) {
                depth(right.path())
                    .cmp(&depth(left.path()))
                    .then_with(|| right.path().cmp(left.path()))
            } else {
                depth(left.path())
                    .cmp(&depth(right.path()))
                    .then_with(|| left.path().cmp(right.path()))
            }
        })
    });
}

/// Whether a relative path is excluded: a pattern without `/` matches a name at
/// any depth, a pattern with `/` matches that relative subtree.
pub fn ignored(relative: &str, patterns: &[String]) -> bool {
    if relative.is_empty() {
        return false;
    }
    let components = relative.split('/').collect::<Vec<_>>();
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim_matches('/');
        if pattern.is_empty() {
            return false;
        }
        if pattern.contains('/') {
            let pattern_components = pattern.split('/').collect::<Vec<_>>();
            components.len() >= pattern_components.len()
                && components[..pattern_components.len()] == pattern_components[..]
        } else {
            components.contains(&pattern)
        }
    })
}

pub const VCS_IGNORES: &[&str] = &[".git", ".svn", ".hg", ".bzr", ".jj"];

/// Join a relative sync path onto a local root.
pub fn local_path(root: &Path, relative: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in relative.split('/').filter(|part| !part.is_empty()) {
        path.push(component);
    }
    path
}

/// Reject a relative path that would leave the synchronized tree.
pub fn ensure_safe_relative(relative: &str) -> Result<()> {
    if relative.is_empty() {
        return Ok(());
    }
    let unsafe_component = relative
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..");
    if unsafe_component || relative.starts_with('/') {
        return Err(SshError::Config(format!(
            "refusing to synchronize the unsafe relative path {relative:?}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

use std::{
    io::Read,
    sync::Arc,
    time::{Duration, Instant, UNIX_EPOCH},
};

use sshai_protocol::WorkspaceFileKind;

use crate::{SftpClient, SshSession, WorkspaceClient, session::join_remote_path};

#[derive(Clone, Debug)]
pub struct SyncOptions {
    pub ignores: Vec<String>,
    pub policy: ConflictPolicy,
    pub propagate_deletes: bool,
    pub dry_run: bool,
    pub state_path: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct CycleReport {
    pub applied: Vec<Action>,
    pub failures: Vec<(Action, String)>,
    pub conflicts: Vec<Conflict>,
    pub withheld_deletes: Vec<(Side, String)>,
    pub local_entries: usize,
    pub remote_entries: usize,
    pub skipped_symlinks: usize,
    pub hashed_local: usize,
    pub hashed_remote: usize,
    pub bytes_to_local: u64,
    pub bytes_to_remote: u64,
    pub unchanged: usize,
    pub dry_run: bool,
    pub duration: Duration,
}

impl CycleReport {
    pub fn is_quiet(&self) -> bool {
        self.applied.is_empty()
            && self.failures.is_empty()
            && self.conflicts.is_empty()
            && self.withheld_deletes.is_empty()
    }
}

#[derive(Default)]
struct ScanResult {
    snapshot: Snapshot,
    cache: BTreeMap<String, CachedDigest>,
    skipped_symlinks: usize,
    hashed: usize,
}

/// One synchronization endpoint pair: a local directory and the remote
/// directory that the session's workspace root points at.
pub struct SyncSession {
    local_root: PathBuf,
    remote_root: String,
    sftp: SftpClient,
    workspace: WorkspaceClient,
    state: SyncState,
    options: SyncOptions,
}

impl SyncSession {
    pub async fn open(
        session: &Arc<SshSession>,
        local_root: &Path,
        remote_root: &str,
        options: SyncOptions,
    ) -> Result<Self> {
        std::fs::create_dir_all(local_root).map_err(SshError::Io)?;
        let local_root = local_root.canonicalize().map_err(SshError::Io)?;
        // Paths are absolute on the wire, so the client is opened without a base.
        let sftp = session.sftp_at_root(None).await?;
        let home = sftp.remote_home().await?;
        let requested = absolute_remote_path(&home, remote_root);
        sftp.create_dir_all(requested.clone()).await?;
        let mut workspace = session.workspace().await?;
        let (root, _capabilities) = workspace.open().await?;
        let canonical = sftp.canonicalize(requested.clone()).await?;
        if root != canonical {
            workspace.close().await?;
            sftp.close().await?;
            return Err(SshError::Config(format!(
                "the remote worker is rooted at {root} instead of {canonical}; \
                 open the session with the synchronized directory as its target path"
            )));
        }
        let state = load_state(&options.state_path)?;
        Ok(Self {
            local_root,
            remote_root: root,
            sftp,
            workspace,
            state,
            options,
        })
    }

    pub fn local_root(&self) -> &Path {
        &self.local_root
    }

    pub fn remote_root(&self) -> &str {
        &self.remote_root
    }

    pub fn state_path(&self) -> &Path {
        &self.options.state_path
    }

    /// Whether this endpoint pair has synchronized before.
    pub fn has_ancestor(&self) -> bool {
        !self.state.ancestor.is_empty()
    }

    pub async fn close(mut self) -> Result<()> {
        let workspace = self.workspace.close().await;
        let sftp = self.sftp.close().await;
        workspace.and(sftp)
    }

    /// Scan both sides, reconcile against the ancestor, and apply the plan.
    pub async fn cycle(&mut self) -> Result<CycleReport> {
        let started = Instant::now();
        let local = self.scan_local().await?;
        let remote = self.scan_remote().await?;
        let plan = reconcile(
            &self.state.ancestor,
            &local.snapshot,
            &remote.snapshot,
            ReconcileOptions {
                policy: self.options.policy,
                propagate_deletes: self.options.propagate_deletes,
            },
        );
        let mut report = CycleReport {
            conflicts: plan.conflicts.clone(),
            withheld_deletes: plan.withheld_deletes.clone(),
            local_entries: local.snapshot.entries.len(),
            remote_entries: remote.snapshot.entries.len(),
            skipped_symlinks: local.skipped_symlinks + remote.skipped_symlinks,
            hashed_local: local.hashed,
            hashed_remote: remote.hashed,
            unchanged: plan.unchanged,
            dry_run: self.options.dry_run,
            ..CycleReport::default()
        };
        self.state.local_cache = local.cache;
        self.state.remote_cache = remote.cache;

        if self.options.dry_run {
            report.applied = plan.actions;
            report.duration = started.elapsed();
            return Ok(report);
        }

        let mut ancestor = plan.ancestor;
        for action in plan.actions {
            match self.apply(&action, &local.snapshot, &remote.snapshot).await {
                Ok(bytes) => {
                    match action.side() {
                        Side::Local => report.bytes_to_local += bytes,
                        Side::Remote => report.bytes_to_remote += bytes,
                    }
                    report.applied.push(action);
                }
                Err(error) => {
                    // A path that could not be applied must not enter the
                    // ancestor, so the next cycle sees the change again.
                    match self.state.ancestor.get(action.path()) {
                        Some(previous) => {
                            ancestor.insert(action.path().to_owned(), previous.clone());
                        }
                        None => {
                            ancestor.remove(action.path());
                        }
                    }
                    report.failures.push((action, format!("{error}")));
                }
            }
        }
        self.state.ancestor = ancestor;
        save_state(&self.options.state_path, &self.state)?;
        report.duration = started.elapsed();
        Ok(report)
    }

    async fn apply(&mut self, action: &Action, local: &Snapshot, remote: &Snapshot) -> Result<u64> {
        ensure_safe_relative(action.path())?;
        match action {
            Action::CreateDirectory { side, path } => {
                match side {
                    Side::Local => {
                        let target = local_path(&self.local_root, path);
                        std::fs::create_dir_all(&target).map_err(SshError::Io)?;
                    }
                    Side::Remote => {
                        self.sftp.create_dir_all(self.remote_path(path)).await?;
                    }
                }
                Ok(0)
            }
            Action::CopyFile { to, path } => match to {
                Side::Local => {
                    let target = local_path(&self.local_root, path);
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent).map_err(SshError::Io)?;
                    }
                    let bytes = self
                        .sftp
                        .download(self.remote_path(path), &target, true)
                        .await?;
                    if let Some(entry) = remote.entries.get(path) {
                        set_local_executable(&target, entry.executable)?;
                    }
                    self.refresh_local_cache(path, remote.entries.get(path))?;
                    Ok(bytes)
                }
                Side::Remote => {
                    let source = local_path(&self.local_root, path);
                    let remote_path = self.remote_path(path);
                    self.sftp.ensure_parent_dir(&remote_path).await?;
                    let bytes = self.sftp.upload(&source, remote_path.clone(), true).await?;
                    if let Some(entry) = local.entries.get(path) {
                        self.sftp
                            .set_permissions(
                                remote_path.clone(),
                                if entry.executable { 0o755 } else { 0o644 },
                            )
                            .await?;
                    }
                    self.refresh_remote_cache(path, local.entries.get(path))
                        .await?;
                    Ok(bytes)
                }
            },
            Action::Delete {
                side,
                path,
                directory,
            } => {
                match side {
                    Side::Local => {
                        let target = local_path(&self.local_root, path);
                        if *directory {
                            // Never recursive: anything left inside was ignored
                            // rather than synchronized, and must survive.
                            std::fs::remove_dir(&target).map_err(SshError::Io)?;
                        } else {
                            std::fs::remove_file(&target).map_err(SshError::Io)?;
                        }
                        self.state.local_cache.remove(path);
                    }
                    Side::Remote => {
                        self.workspace.remove(path.clone(), false).await?;
                        self.state.remote_cache.remove(path);
                    }
                }
                Ok(0)
            }
        }
    }

    fn remote_path(&self, relative: &str) -> String {
        join_remote_path(&self.remote_root, relative)
    }

    /// Record the destination's own metadata so the next scan does not rehash a
    /// file this cycle just wrote.
    fn refresh_local_cache(&mut self, path: &str, source: Option<&Entry>) -> Result<()> {
        let Some(digest) = source.and_then(|entry| entry.digest.clone()) else {
            return Ok(());
        };
        let target = local_path(&self.local_root, path);
        let metadata = std::fs::metadata(&target).map_err(SshError::Io)?;
        self.state.local_cache.insert(
            path.to_owned(),
            CachedDigest {
                size: metadata.len(),
                modified_ms: local_modified_ms(&metadata),
                digest,
            },
        );
        Ok(())
    }

    async fn refresh_remote_cache(&mut self, path: &str, source: Option<&Entry>) -> Result<()> {
        let Some(digest) = source.and_then(|entry| entry.digest.clone()) else {
            return Ok(());
        };
        let metadata = self.workspace.stat(path.to_owned()).await?;
        self.state.remote_cache.insert(
            path.to_owned(),
            CachedDigest {
                size: metadata.size,
                // A scan reads this timestamp back over SFTP, which carries
                // whole seconds, so the cache has to store it the same way.
                modified_ms: metadata.modified_unix_ms.map(truncate_to_seconds),
                digest,
            },
        );
        Ok(())
    }

    async fn scan_local(&self) -> Result<ScanResult> {
        let root = self.local_root.clone();
        let ignores = self.options.ignores.clone();
        let cache = self.state.local_cache.clone();
        // The local walk is plain blocking filesystem work, hashing included.
        tokio::task::spawn_blocking(move || scan_local_tree(&root, &ignores, &cache))
            .await
            .map_err(|error| SshError::Config(format!("local scan task failed: {error}")))?
    }

    async fn scan_remote(&mut self) -> Result<ScanResult> {
        let mut result = ScanResult::default();
        let mut directories = vec![String::new()];
        while let Some(relative) = directories.pop() {
            let listing = self
                .sftp
                .read_dir_entries(&self.remote_path(&relative))
                .await?;
            for entry in listing {
                let child = if relative.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{relative}/{}", entry.name)
                };
                if ignored(&child, &self.options.ignores) {
                    result.snapshot.ignored_parents.insert(relative.clone());
                    continue;
                }
                if result.snapshot.entries.len() >= MAX_SYNC_ENTRIES {
                    return Err(SshError::Config(format!(
                        "the remote tree exceeds {MAX_SYNC_ENTRIES} entries; narrow it with --ignore"
                    )));
                }
                match entry.kind {
                    WorkspaceFileKind::Directory => {
                        result.snapshot.insert(child.clone(), Entry::directory());
                        directories.push(child);
                    }
                    WorkspaceFileKind::File => {
                        let digest = match cached_digest(
                            &self.state.remote_cache,
                            &child,
                            entry.size,
                            entry.modified_ms,
                        ) {
                            Some(digest) => digest,
                            None => {
                                result.hashed += 1;
                                let (_algorithm, digest) =
                                    self.workspace.hash(child.clone()).await?;
                                digest
                            }
                        };
                        result.cache.insert(
                            child.clone(),
                            CachedDigest {
                                size: entry.size,
                                modified_ms: entry.modified_ms,
                                digest: digest.clone(),
                            },
                        );
                        result.snapshot.insert(
                            child,
                            Entry::file(entry.size, entry.modified_ms, entry.executable, &digest),
                        );
                    }
                    // Symlinks and special files stay out of the synchronized set.
                    _ => result.skipped_symlinks += 1,
                }
            }
        }
        Ok(result)
    }
}

fn scan_local_tree(
    root: &Path,
    ignores: &[String],
    cache: &BTreeMap<String, CachedDigest>,
) -> Result<ScanResult> {
    let mut result = ScanResult::default();
    let mut directories = vec![String::new()];
    while let Some(relative) = directories.pop() {
        let directory = local_path(root, &relative);
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&directory).map_err(SshError::Io)? {
            names.push(entry.map_err(SshError::Io)?);
        }
        for entry in names {
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            if ignored(&child, ignores) {
                result.snapshot.ignored_parents.insert(relative.clone());
                continue;
            }
            if result.snapshot.entries.len() >= MAX_SYNC_ENTRIES {
                return Err(SshError::Config(format!(
                    "the local tree exceeds {MAX_SYNC_ENTRIES} entries; narrow it with --ignore"
                )));
            }
            let metadata = entry.metadata().map_err(SshError::Io)?;
            let kind = metadata.file_type();
            if kind.is_symlink() {
                result.skipped_symlinks += 1;
                continue;
            }
            if kind.is_dir() {
                result.snapshot.insert(child.clone(), Entry::directory());
                directories.push(child);
                continue;
            }
            if !kind.is_file() {
                result.skipped_symlinks += 1;
                continue;
            }
            let size = metadata.len();
            let modified_ms = local_modified_ms(&metadata);
            let digest = match cached_digest(cache, &child, size, modified_ms) {
                Some(digest) => digest,
                None => {
                    result.hashed += 1;
                    hash_local_file(&local_path(root, &child))?
                }
            };
            result.cache.insert(
                child.clone(),
                CachedDigest {
                    size,
                    modified_ms,
                    digest: digest.clone(),
                },
            );
            result.snapshot.insert(
                child,
                Entry::file(size, modified_ms, local_executable(&metadata), &digest),
            );
        }
    }
    Ok(result)
}

/// SFTP timestamps have one-second resolution.
fn truncate_to_seconds(milliseconds: u64) -> u64 {
    milliseconds / 1000 * 1000
}

fn cached_digest(
    cache: &BTreeMap<String, CachedDigest>,
    path: &str,
    size: u64,
    modified_ms: Option<u64>,
) -> Option<String> {
    let cached = cache.get(path)?;
    // Without a timestamp on either side the digest has to be recomputed.
    let timestamps_match = match (cached.modified_ms, modified_ms) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    };
    (cached.size == size && timestamps_match).then(|| cached.digest.clone())
}

fn hash_local_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path).map_err(SshError::Io)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(SshError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn local_modified_ms(metadata: &std::fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_millis() as u64)
}

#[cfg(unix)]
fn local_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn local_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_local_executable(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(SshError::Io)
}

#[cfg(not(unix))]
fn set_local_executable(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

fn absolute_remote_path(home: &str, path: &str) -> String {
    if path.starts_with('/') {
        let trimmed = path.trim_end_matches('/');
        return if trimmed.is_empty() {
            "/".to_owned()
        } else {
            trimmed.to_owned()
        };
    }
    let relative = match path.strip_prefix('~') {
        Some("") => "",
        Some(rest) if rest.starts_with('/') => rest.trim_start_matches('/'),
        _ => path,
    };
    let relative = relative.trim_start_matches("./").trim_end_matches('/');
    if relative.is_empty() {
        home.trim_end_matches('/').to_owned()
    } else {
        join_remote_path(home, relative)
    }
}

fn load_state(path: &Path) -> Result<SyncState> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Ok(SyncState::default());
    };
    match serde_json::from_str::<SyncState>(&contents) {
        // A state file from another version starts the pair over as a first run,
        // which is safe: a first run never deletes.
        Ok(state) if state.version == SYNC_STATE_VERSION => Ok(state),
        Ok(_) | Err(_) => Ok(SyncState::default()),
    }
}

fn save_state(path: &Path, state: &SyncState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(SshError::Io)?;
    }
    let contents =
        serde_json::to_string(state).map_err(|error| SshError::Config(format!("{error}")))?;
    let temporary = path.with_extension("json.part");
    std::fs::write(&temporary, contents).map_err(SshError::Io)?;
    std::fs::rename(&temporary, path).map_err(SshError::Io)?;
    Ok(())
}

/// A stable state-file name for one endpoint pair.
pub fn state_file_name(local_root: &Path, endpoint: &str, remote_root: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(local_root.to_string_lossy().as_bytes());
    hasher.update(b"\n");
    hasher.update(endpoint.as_bytes());
    hasher.update(b"\n");
    hasher.update(remote_root.as_bytes());
    format!("{}.json", &hasher.finalize().to_hex()[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(digest: &str) -> Entry {
        Entry::file(digest.len() as u64, Some(1_000), false, digest)
    }

    fn timed_file(digest: &str, modified_ms: u64) -> Entry {
        Entry::file(digest.len() as u64, Some(modified_ms), false, digest)
    }

    fn snapshot(entries: &[(&str, Entry)]) -> Snapshot {
        let mut snapshot = Snapshot::default();
        for (path, entry) in entries {
            snapshot.insert(*path, entry.clone());
        }
        snapshot
    }

    fn ancestor(entries: &[(&str, Entry)]) -> BTreeMap<String, AncestorEntry> {
        entries
            .iter()
            .map(|(path, entry)| ((*path).to_owned(), AncestorEntry::from_entry(entry)))
            .collect()
    }

    fn safe() -> ReconcileOptions {
        ReconcileOptions::default()
    }

    #[test]
    fn first_run_copies_each_side_and_adopts_identical_files() {
        let local = snapshot(&[
            ("shared.txt", file("same")),
            ("only_local.txt", file("left")),
            ("dir", Entry::directory()),
            ("dir/deep.txt", file("deep")),
        ]);
        let remote = snapshot(&[
            ("shared.txt", file("same")),
            ("only_remote.txt", file("right")),
        ]);

        let plan = reconcile(&BTreeMap::new(), &local, &remote, safe());

        assert_eq!(
            plan.actions,
            vec![
                Action::CreateDirectory {
                    side: Side::Remote,
                    path: "dir".to_owned()
                },
                Action::CopyFile {
                    to: Side::Remote,
                    path: "only_local.txt".to_owned()
                },
                Action::CopyFile {
                    to: Side::Local,
                    path: "only_remote.txt".to_owned()
                },
                Action::CopyFile {
                    to: Side::Remote,
                    path: "dir/deep.txt".to_owned()
                },
            ]
        );
        assert!(plan.conflicts.is_empty());
        // The file both sides already agree on only enters the ancestor.
        assert_eq!(plan.unchanged, 1);
        assert_eq!(plan.ancestor.len(), 5);
    }

    #[test]
    fn a_first_run_never_deletes_and_reports_differing_files() {
        let local = snapshot(&[("notes.md", file("left"))]);
        let remote = snapshot(&[("notes.md", file("right"))]);

        let plan = reconcile(&BTreeMap::new(), &local, &remote, safe());

        assert!(plan.actions.is_empty());
        assert_eq!(
            plan.conflicts,
            vec![Conflict {
                path: "notes.md".to_owned(),
                reason: ConflictReason::BothChanged
            }]
        );
        assert!(plan.ancestor.is_empty());
    }

    #[test]
    fn a_change_on_one_side_propagates_to_the_other() {
        let base = ancestor(&[("a.txt", file("old")), ("b.txt", file("keep"))]);
        let local = snapshot(&[("a.txt", file("new")), ("b.txt", file("keep"))]);
        let remote = snapshot(&[("a.txt", file("old")), ("b.txt", file("keep"))]);

        let plan = reconcile(&base, &local, &remote, safe());

        assert_eq!(
            plan.actions,
            vec![Action::CopyFile {
                to: Side::Remote,
                path: "a.txt".to_owned()
            }]
        );
        assert_eq!(plan.ancestor["a.txt"].digest.as_deref(), Some("new"));
        assert_eq!(plan.unchanged, 1);
    }

    #[test]
    fn a_deletion_on_one_side_removes_the_other_side() {
        let base = ancestor(&[
            ("gone.txt", file("old")),
            ("dir", Entry::directory()),
            ("dir/inner.txt", file("inner")),
        ]);
        let local = snapshot(&[]);
        let remote = snapshot(&[
            ("gone.txt", file("old")),
            ("dir", Entry::directory()),
            ("dir/inner.txt", file("inner")),
        ]);

        let plan = reconcile(&base, &local, &remote, safe());

        // Children are removed before the directory that holds them.
        assert_eq!(
            plan.actions,
            vec![
                Action::Delete {
                    side: Side::Remote,
                    path: "dir/inner.txt".to_owned(),
                    directory: false
                },
                Action::Delete {
                    side: Side::Remote,
                    path: "gone.txt".to_owned(),
                    directory: false
                },
                Action::Delete {
                    side: Side::Remote,
                    path: "dir".to_owned(),
                    directory: true
                },
            ]
        );
        assert!(plan.ancestor.is_empty());
    }

    #[test]
    fn no_delete_withholds_the_removal_and_keeps_the_ancestor() {
        let base = ancestor(&[("gone.txt", file("old"))]);
        let local = snapshot(&[]);
        let remote = snapshot(&[("gone.txt", file("old"))]);

        let plan = reconcile(
            &base,
            &local,
            &remote,
            ReconcileOptions {
                propagate_deletes: false,
                ..safe()
            },
        );

        assert!(plan.actions.is_empty());
        assert_eq!(
            plan.withheld_deletes,
            vec![(Side::Remote, "gone.txt".to_owned())]
        );
        // Keeping the ancestor means the deletion is offered again next cycle.
        assert!(plan.ancestor.contains_key("gone.txt"));
    }

    #[test]
    fn both_sides_changing_is_a_conflict_that_keeps_the_ancestor() {
        let base = ancestor(&[("notes.md", file("old"))]);
        let local = snapshot(&[("notes.md", file("mine"))]);
        let remote = snapshot(&[("notes.md", file("theirs"))]);

        let plan = reconcile(&base, &local, &remote, safe());

        assert!(plan.actions.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.ancestor["notes.md"].digest.as_deref(), Some("old"));
    }

    #[test]
    fn a_policy_resolves_a_conflict_towards_one_side() {
        let base = ancestor(&[("notes.md", file("old"))]);
        let local = snapshot(&[("notes.md", file("mine"))]);
        let remote = snapshot(&[("notes.md", file("theirs"))]);

        for (policy, expected) in [
            (ConflictPolicy::Local, Side::Remote),
            (ConflictPolicy::Remote, Side::Local),
        ] {
            let plan = reconcile(
                &base,
                &local,
                &remote,
                ReconcileOptions { policy, ..safe() },
            );
            assert_eq!(
                plan.actions,
                vec![Action::CopyFile {
                    to: expected,
                    path: "notes.md".to_owned()
                }],
                "policy {policy:?}"
            );
            assert!(plan.conflicts.is_empty(), "policy {policy:?}");
        }
    }

    #[test]
    fn newest_wins_only_with_usable_timestamps() {
        let base = ancestor(&[("notes.md", file("old"))]);
        let local = snapshot(&[("notes.md", timed_file("mine", 2_000))]);
        let remote = snapshot(&[("notes.md", timed_file("theirs", 5_000))]);
        let options = ReconcileOptions {
            policy: ConflictPolicy::Newest,
            ..safe()
        };

        let plan = reconcile(&base, &local, &remote, options);
        assert_eq!(
            plan.actions,
            vec![Action::CopyFile {
                to: Side::Local,
                path: "notes.md".to_owned()
            }]
        );

        // Equal timestamps cannot decide, so the path stays a conflict.
        let tied = snapshot(&[("notes.md", timed_file("theirs", 2_000))]);
        let plan = reconcile(&base, &local, &tied, options);
        assert!(plan.actions.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
    }

    #[test]
    fn deleting_on_one_side_while_the_other_changes_is_a_conflict() {
        let base = ancestor(&[("notes.md", file("old"))]);
        let local = snapshot(&[]);
        let remote = snapshot(&[("notes.md", file("theirs"))]);

        let plan = reconcile(&base, &local, &remote, safe());
        assert_eq!(
            plan.conflicts,
            vec![Conflict {
                path: "notes.md".to_owned(),
                reason: ConflictReason::DeletedAndChanged {
                    deleted: Side::Local
                }
            }]
        );

        // `--conflict remote` restores the file the local side deleted.
        let plan = reconcile(
            &base,
            &local,
            &remote,
            ReconcileOptions {
                policy: ConflictPolicy::Remote,
                ..safe()
            },
        );
        assert_eq!(
            plan.actions,
            vec![Action::CopyFile {
                to: Side::Local,
                path: "notes.md".to_owned()
            }]
        );

        // `--conflict local` lets the deletion win.
        let plan = reconcile(
            &base,
            &local,
            &remote,
            ReconcileOptions {
                policy: ConflictPolicy::Local,
                ..safe()
            },
        );
        assert_eq!(
            plan.actions,
            vec![Action::Delete {
                side: Side::Remote,
                path: "notes.md".to_owned(),
                directory: false
            }]
        );
    }

    #[test]
    fn replacing_a_directory_with_a_file_needs_an_explicit_policy() {
        let base = ancestor(&[("thing", Entry::directory())]);
        let local = snapshot(&[("thing", file("now a file"))]);
        let remote = snapshot(&[("thing", Entry::directory())]);

        let plan = reconcile(&base, &local, &remote, safe());
        assert!(plan.actions.is_empty());
        assert_eq!(
            plan.conflicts,
            vec![Conflict {
                path: "thing".to_owned(),
                reason: ConflictReason::KindMismatch
            }]
        );

        let plan = reconcile(
            &base,
            &local,
            &remote,
            ReconcileOptions {
                policy: ConflictPolicy::Local,
                ..safe()
            },
        );
        // The directory is cleared before the file that replaces it.
        assert_eq!(
            plan.actions,
            vec![
                Action::Delete {
                    side: Side::Remote,
                    path: "thing".to_owned(),
                    directory: true
                },
                Action::CopyFile {
                    to: Side::Remote,
                    path: "thing".to_owned()
                },
            ]
        );
    }

    #[test]
    fn a_clearing_delete_runs_before_the_replacement_but_after_nothing_else() {
        let base = ancestor(&[
            ("thing", Entry::directory()),
            ("thing/inner.txt", file("inner")),
            ("stale.txt", file("stale")),
        ]);
        // Locally `thing` became a file and `stale.txt` was removed.
        let local = snapshot(&[("thing", file("now a file"))]);
        let remote = snapshot(&[
            ("thing", Entry::directory()),
            ("thing/inner.txt", file("inner")),
            ("stale.txt", file("stale")),
        ]);

        let plan = reconcile(
            &base,
            &local,
            &remote,
            ReconcileOptions {
                policy: ConflictPolicy::Local,
                ..safe()
            },
        );

        // The directory is emptied, then removed, then replaced by the file;
        // the unrelated deletion comes last.
        assert_eq!(
            plan.actions,
            vec![
                Action::Delete {
                    side: Side::Remote,
                    path: "thing/inner.txt".to_owned(),
                    directory: false
                },
                Action::Delete {
                    side: Side::Remote,
                    path: "thing".to_owned(),
                    directory: true
                },
                Action::CopyFile {
                    to: Side::Remote,
                    path: "thing".to_owned()
                },
                Action::Delete {
                    side: Side::Remote,
                    path: "stale.txt".to_owned(),
                    directory: false
                },
            ]
        );
    }

    #[test]
    fn a_directory_holding_new_content_is_not_deleted() {
        let base = ancestor(&[
            ("dir", Entry::directory()),
            ("dir/old.txt", file("old")),
            ("other", Entry::directory()),
            ("other/gone.txt", file("gone")),
        ]);
        // The remote dropped both directories; the local side meanwhile added a
        // file inside the first one.
        let local = snapshot(&[
            ("dir", Entry::directory()),
            ("dir/old.txt", file("old")),
            ("dir/new.txt", file("new")),
            ("other", Entry::directory()),
            ("other/gone.txt", file("gone")),
        ]);
        let remote = snapshot(&[]);

        let plan = reconcile(&base, &local, &remote, safe());

        // `dir` survives with everything inside it, and is reported instead.
        assert_eq!(
            plan.conflicts,
            vec![Conflict {
                path: "dir".to_owned(),
                reason: ConflictReason::DirectoryHasChanges {
                    deleted: Side::Remote
                }
            }]
        );
        assert!(plan.ancestor.contains_key("dir"));
        // The file the remote removed still goes; only the directory stays.
        assert!(!plan.ancestor.contains_key("dir/old.txt"));
        assert_eq!(
            plan.actions,
            vec![
                Action::CopyFile {
                    to: Side::Remote,
                    path: "dir/new.txt".to_owned()
                },
                Action::Delete {
                    side: Side::Local,
                    path: "other/gone.txt".to_owned(),
                    directory: false
                },
                Action::Delete {
                    side: Side::Local,
                    path: "dir/old.txt".to_owned(),
                    directory: false
                },
                Action::Delete {
                    side: Side::Local,
                    path: "other".to_owned(),
                    directory: true
                },
            ]
        );
        // The directory that really is empty on both sides is forgotten.
        assert!(!plan.ancestor.contains_key("other"));
    }

    #[test]
    fn a_directory_holding_ignored_content_is_not_deleted() {
        let base = ancestor(&[
            ("tools", Entry::directory()),
            ("tools/kept.txt", file("kept")),
        ]);
        let mut local = snapshot(&[
            ("tools", Entry::directory()),
            ("tools/kept.txt", file("kept")),
        ]);
        // The local scan saw an ignored child inside `tools`.
        local.ignored_parents.insert("tools".to_owned());
        let remote = snapshot(&[]);

        let plan = reconcile(&base, &local, &remote, safe());

        // The synchronized file goes, the directory and its ignored content stay.
        assert_eq!(
            plan.actions,
            vec![Action::Delete {
                side: Side::Local,
                path: "tools/kept.txt".to_owned(),
                directory: false
            }]
        );
        assert_eq!(
            plan.conflicts,
            vec![Conflict {
                path: "tools".to_owned(),
                reason: ConflictReason::DirectoryHoldsIgnored {
                    deleted: Side::Remote
                }
            }]
        );
        assert!(plan.ancestor.contains_key("tools"));
    }

    #[test]
    fn a_local_scan_notes_the_directories_that_hold_ignored_children() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir_all(root.join("tools/.git")).unwrap();
        std::fs::write(root.join("tools/.git/HEAD"), b"ref").unwrap();
        std::fs::write(root.join("tools/kept.txt"), b"kept").unwrap();

        let scan = scan_local_tree(root, &[".git".to_owned()], &BTreeMap::new()).unwrap();

        assert_eq!(
            scan.snapshot.ignored_parents.iter().collect::<Vec<_>>(),
            vec!["tools"]
        );
        assert!(!scan.snapshot.entries.contains_key("tools/.git"));
    }

    #[test]
    fn a_changed_executable_bit_propagates() {
        let base = ancestor(&[("run.sh", file("script"))]);
        let mut executable = file("script");
        executable.executable = true;
        let local = snapshot(&[("run.sh", executable)]);
        let remote = snapshot(&[("run.sh", file("script"))]);

        let plan = reconcile(&base, &local, &remote, safe());

        assert_eq!(
            plan.actions,
            vec![Action::CopyFile {
                to: Side::Remote,
                path: "run.sh".to_owned()
            }]
        );
        assert!(plan.ancestor["run.sh"].executable);
    }

    #[test]
    fn both_sides_deleting_forgets_the_path() {
        let base = ancestor(&[("gone.txt", file("old"))]);
        let plan = reconcile(&base, &snapshot(&[]), &snapshot(&[]), safe());
        assert!(plan.actions.is_empty());
        assert!(plan.ancestor.is_empty());
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn directories_are_created_before_the_files_inside_them() {
        let local = snapshot(&[
            ("a/b/c/deep.txt", file("deep")),
            ("a", Entry::directory()),
            ("a/b", Entry::directory()),
            ("a/b/c", Entry::directory()),
        ]);
        let plan = reconcile(&BTreeMap::new(), &local, &snapshot(&[]), safe());
        let paths = plan
            .actions
            .iter()
            .map(|action| action.path().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["a", "a/b", "a/b/c", "a/b/c/deep.txt"]);
    }

    #[test]
    fn ignore_patterns_match_names_at_any_depth_and_relative_subtrees() {
        let patterns = vec![
            "node_modules".to_owned(),
            "build/cache".to_owned(),
            ".git".to_owned(),
        ];
        assert!(ignored("node_modules", &patterns));
        assert!(ignored("web/node_modules/left-pad/index.js", &patterns));
        assert!(ignored("build/cache", &patterns));
        assert!(ignored("build/cache/objects/a.o", &patterns));
        assert!(!ignored("build/output", &patterns));
        // A relative pattern only matches from the root of the tree.
        assert!(!ignored("web/build/cache", &patterns));
        assert!(ignored(".git/config", &patterns));
        assert!(!ignored("", &patterns));
    }

    #[test]
    fn unsafe_relative_paths_are_refused() {
        assert!(ensure_safe_relative("a/b.txt").is_ok());
        assert!(ensure_safe_relative("").is_ok());
        assert!(ensure_safe_relative("../escape").is_err());
        assert!(ensure_safe_relative("a/../../escape").is_err());
        assert!(ensure_safe_relative("/absolute").is_err());
        assert!(ensure_safe_relative("a//b").is_err());
        assert_eq!(
            local_path(Path::new("/tmp/root"), "a/b.txt"),
            PathBuf::from("/tmp/root/a/b.txt")
        );
    }

    #[test]
    fn remote_timestamps_are_cached_at_the_resolution_a_scan_reads_back() {
        assert_eq!(truncate_to_seconds(1_757_000_123_456), 1_757_000_123_000);
        assert_eq!(truncate_to_seconds(1_000), 1_000);
        assert_eq!(truncate_to_seconds(999), 0);
    }

    #[test]
    fn a_cached_digest_is_reused_only_for_identical_metadata() {
        let mut cache = BTreeMap::new();
        cache.insert(
            "a.txt".to_owned(),
            CachedDigest {
                size: 4,
                modified_ms: Some(1_000),
                digest: "cached".to_owned(),
            },
        );
        assert_eq!(
            cached_digest(&cache, "a.txt", 4, Some(1_000)).as_deref(),
            Some("cached")
        );
        assert_eq!(cached_digest(&cache, "a.txt", 5, Some(1_000)), None);
        assert_eq!(cached_digest(&cache, "a.txt", 4, Some(2_000)), None);
        // A side without timestamps has to rehash every cycle.
        assert_eq!(cached_digest(&cache, "a.txt", 4, None), None);
        assert_eq!(cached_digest(&cache, "missing", 4, Some(1_000)), None);
    }

    #[test]
    fn remote_roots_resolve_against_the_remote_home() {
        assert_eq!(absolute_remote_path("/home/ka", "/srv/app/"), "/srv/app");
        assert_eq!(absolute_remote_path("/home/ka", "~/work"), "/home/ka/work");
        assert_eq!(absolute_remote_path("/home/ka", "~"), "/home/ka");
        assert_eq!(
            absolute_remote_path("/home/ka", "work/x"),
            "/home/ka/work/x"
        );
        assert_eq!(absolute_remote_path("/home/ka", "./work"), "/home/ka/work");
        assert_eq!(absolute_remote_path("/home/ka", "/"), "/");
    }

    #[test]
    fn state_survives_a_round_trip_and_ignores_a_foreign_version() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let mut state = SyncState::default();
        state.ancestor.insert(
            "a.txt".to_owned(),
            AncestorEntry::from_entry(&file("digest")),
        );
        state.local_cache.insert(
            "a.txt".to_owned(),
            CachedDigest {
                size: 6,
                modified_ms: Some(7),
                digest: "digest".to_owned(),
            },
        );
        save_state(&path, &state).unwrap();

        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded.ancestor, state.ancestor);
        assert_eq!(loaded.local_cache, state.local_cache);

        // A missing file and an unknown version both start over.
        assert!(
            load_state(&directory.path().join("absent.json"))
                .unwrap()
                .ancestor
                .is_empty()
        );
        std::fs::write(&path, r#"{"version":999,"ancestor":{"a":{"kind":"file"}}}"#).unwrap();
        assert!(load_state(&path).unwrap().ancestor.is_empty());
    }

    #[test]
    fn state_file_names_are_stable_per_endpoint_pair() {
        let first = state_file_name(Path::new("/home/ka/app"), "ka@host:22", "/srv/app");
        let same = state_file_name(Path::new("/home/ka/app"), "ka@host:22", "/srv/app");
        let other = state_file_name(Path::new("/home/ka/app"), "ka@host:22", "/srv/other");
        assert_eq!(first, same);
        assert_ne!(first, other);
        assert!(first.ends_with(".json"));
        assert_eq!(first.len(), 32 + ".json".len());
    }

    #[test]
    fn a_local_scan_hashes_files_and_skips_ignored_names() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), b"x").unwrap();

        let ignores = vec!["node_modules".to_owned()];
        let scan = scan_local_tree(root, &ignores, &BTreeMap::new()).unwrap();

        assert_eq!(
            scan.snapshot.entries.keys().collect::<Vec<_>>(),
            vec!["src", "src/main.rs"]
        );
        assert_eq!(scan.hashed, 1);
        let digest = scan.snapshot.entries["src/main.rs"].digest.clone().unwrap();
        assert_eq!(digest, blake3::hash(b"fn main() {}").to_hex().to_string());

        // A second scan with the cache from the first one hashes nothing.
        let again = scan_local_tree(root, &ignores, &scan.cache).unwrap();
        assert_eq!(again.hashed, 0);
        assert_eq!(again.snapshot.entries, scan.snapshot.entries);
    }

    #[cfg(unix)]
    #[test]
    fn a_local_scan_records_the_executable_bit_and_skips_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::write(root.join("run.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(root.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::write(root.join("plain.txt"), b"text").unwrap();
        symlink(root.join("plain.txt"), root.join("link.txt")).unwrap();

        let scan = scan_local_tree(root, &[], &BTreeMap::new()).unwrap();

        assert!(scan.snapshot.entries["run.sh"].executable);
        assert!(!scan.snapshot.entries["plain.txt"].executable);
        assert!(!scan.snapshot.entries.contains_key("link.txt"));
        assert_eq!(scan.skipped_symlinks, 1);
    }
}
