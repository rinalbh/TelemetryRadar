//! Resolve selected PIDs to executable paths and follow their instances/children.
use crate::{Error, Result};
use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

/// Shared packet-capture and interception scope. System capture needs no PID discovery.
#[derive(Clone, Debug, Default)]
pub enum CaptureScope {
    #[default]
    System,
    ProcessTrees(ProcessSelection),
}

impl CaptureScope {
    pub(crate) fn tracker(&self) -> Result<Option<ProcessTree>> {
        match self {
            Self::System => Ok(None),
            Self::ProcessTrees(selection) => {
                ProcessTree::from_selection(selection.clone()).map(Some)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Unix timestamp in seconds, as supplied by sysinfo.
    pub start_time: u64,
}

#[derive(Clone, Debug)]
pub struct SelectedProcess {
    pub identity: ProcessIdentity,
    pub image: PathBuf,
}

/// Immutable selection resolved while the user-picked PIDs still exist.
/// Image means the full executable path (including filesystem aliases), not
/// just its basename or a content hash.
/// All instances of those paths and their descendants are followed, across exits
/// and restarts. A different installation/version directory is a different image.
#[derive(Clone, Debug, Default)]
pub struct ProcessSelection {
    processes: Vec<SelectedProcess>,
    images: Vec<PathBuf>,
}
impl ProcessSelection {
    /// Blocking OS query: call from a GUI's task executor when PIDs are selected.
    /// Capture may start later, even after every original PID has exited.
    pub fn from_pids(pids: &[u32]) -> Result<Self> {
        if pids.is_empty() || pids.contains(&0) {
            return Err(Error::Invalid("Provide at least one nonzero PID".into()));
        }
        let pids: Vec<_> = pids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(Pid::from_u32)
            .collect();
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessesToUpdate::Some(&pids), true, refresh_kind());
        let mut processes = Vec::new();
        let mut images: Vec<PathBuf> = Vec::new();
        for pid in pids {
            let process = system.process(pid).ok_or_else(|| {
                Error::Invalid(format!(
                    "Selected PID {pid} does not exist or is inaccessible"
                ))
            })?;
            let image = process.exe().filter(|p| p.is_absolute()).ok_or_else(|| {
                Error::Invalid(format!("Cannot resolve executable image for PID {pid}"))
            })?;
            let image = image.canonicalize().map_err(|e| {
                Error::Invalid(format!(
                    "Cannot resolve image {} for PID {pid}: {e}",
                    image.display()
                ))
            })?;
            if !images.iter().any(|p| same_image(p, &image)) {
                images.push(image.clone());
            }
            processes.push(SelectedProcess {
                identity: ProcessIdentity {
                    pid: pid.as_u32(),
                    start_time: process.start_time(),
                },
                image,
            });
        }
        images.sort();
        Ok(Self { processes, images })
    }
    pub fn processes(&self) -> &[SelectedProcess] {
        &self.processes
    }
    pub fn images(&self) -> &[PathBuf] {
        &self.images
    }
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }
}

#[derive(Clone, Debug)]
struct Entry {
    identity: ProcessIdentity,
    parent: Option<u32>,
    image: Option<PathBuf>,
}

fn refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .without_tasks()
        .with_exe(UpdateKind::Always)
}

fn same_image(left: &Path, right: &Path) -> bool {
    left == right || same_file::is_same_file(left, right).unwrap_or(false)
}

/// Polling tracker retaining original and discovered identities after exit.
/// Processes that start and exit entirely between polls can still be missed.
pub struct ProcessTree {
    system: System,
    selection: ProcessSelection,
    known: BTreeSet<ProcessIdentity>,
}
impl ProcessTree {
    pub fn new(pids: &[u32]) -> Result<Self> {
        Self::from_selection(ProcessSelection::from_pids(pids)?)
    }

    /// Uses the resolved selection without looking up the original PIDs again.
    pub fn from_selection(selection: ProcessSelection) -> Result<Self> {
        if selection.is_empty() {
            return Err(Error::Invalid(
                "Select executable images before starting capture".into(),
            ));
        }
        let known = selection.processes.iter().map(|p| p.identity).collect();
        Ok(Self {
            system: System::new(),
            selection,
            known,
        })
    }

    pub fn selection(&self) -> &ProcessSelection {
        &self.selection
    }

    fn snapshot(&mut self) -> HashMap<u32, Entry> {
        self.system
            .refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
        // Canonicalize each distinct executable once per snapshot, not per instance.
        let mut images: HashMap<PathBuf, PathBuf> = HashMap::new();
        self.system
            .processes()
            .iter()
            .map(|(pid, process)| {
                let image = process.exe().filter(|p| p.is_absolute()).map(|path| {
                    images
                        .entry(path.to_owned())
                        .or_insert_with(|| path.canonicalize().unwrap_or_else(|_| path.to_owned()))
                        .clone()
                });
                (
                    pid.as_u32(),
                    Entry {
                        identity: ProcessIdentity {
                            pid: pid.as_u32(),
                            start_time: process.start_time(),
                        },
                        parent: process.parent().map(|p| p.as_u32()),
                        image,
                    },
                )
            })
            .collect()
    }

    fn expand(&mut self, snapshot: &HashMap<u32, Entry>) {
        // Executable matches are roots independently of their launcher or ancestry.
        let mut matches = HashMap::new();
        for entry in snapshot.values() {
            if entry.image.as_ref().is_some_and(|image| {
                *matches.entry(image).or_insert_with(|| {
                    self.selection
                        .images
                        .iter()
                        .any(|selected| same_image(selected, image))
                })
            }) {
                self.known.insert(entry.identity);
            }
        }
        loop {
            let before = self.known.len();
            for entry in snapshot.values() {
                if let Some(parent) = entry.parent.and_then(|p| snapshot.get(&p))
                    && self.known.contains(&parent.identity)
                    && parent.identity.start_time <= entry.identity.start_time
                {
                    self.known.insert(entry.identity);
                }
            }
            if self.known.len() == before {
                break;
            }
        }
    }

    pub fn refresh(&mut self) -> Vec<ProcessIdentity> {
        let snapshot = self.snapshot();
        self.expand(&snapshot);
        self.identities()
    }
    /// Current selected instances/descendants only, for live interception specs.
    /// Historical identities remain available through identities().
    pub fn refresh_active(&mut self) -> Vec<ProcessIdentity> {
        let snapshot = self.snapshot();
        self.expand(&snapshot);
        let mut active: Vec<_> = snapshot
            .values()
            .map(|entry| entry.identity)
            .filter(|identity| self.known.contains(identity))
            .collect();
        active.sort();
        active
    }
    pub fn identities(&self) -> Vec<ProcessIdentity> {
        self.known.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(pid: u32, start: u64, parent: Option<u32>, image: &str) -> (u32, Entry) {
        (
            pid,
            Entry {
                identity: ProcessIdentity {
                    pid,
                    start_time: start,
                },
                parent,
                image: Some(image.into()),
            },
        )
    }
    fn tree() -> ProcessTree {
        ProcessTree::from_selection(ProcessSelection {
            processes: vec![SelectedProcess {
                identity: ProcessIdentity {
                    pid: 10,
                    start_time: 1,
                },
                image: "/app/client".into(),
            }],
            images: vec!["/app/client".into()],
        })
        .unwrap()
    }
    #[test]
    fn follows_restarted_image_and_children_after_all_original_pids_exit() {
        let mut tree = tree();
        tree.expand(&HashMap::new());
        assert_eq!(tree.identities().len(), 1);
        tree.expand(
            &[
                entry(90, 100, None, "/app/client"),
                entry(91, 101, Some(90), "/helpers/renderer"),
                entry(92, 102, Some(91), "/helpers/worker"),
            ]
            .into(),
        );
        assert_eq!(tree.identities().len(), 4);
        tree.expand(&[entry(200, 200, None, "/app/client")].into());
        assert!(tree.known.contains(&ProcessIdentity {
            pid: 200,
            start_time: 200
        }));
    }
    #[test]
    fn reused_pid_and_same_basename_elsewhere_do_not_match() {
        let mut tree = tree();
        tree.expand(
            &[
                entry(10, 100, None, "/other/client"),
                entry(40, 101, Some(10), "/other/child"),
                entry(50, 100, None, "/other/client"),
            ]
            .into(),
        );
        assert_eq!(tree.identities().len(), 1);
    }
    #[test]
    fn child_images_do_not_become_independent_roots() {
        let mut tree = tree();
        tree.expand(
            &[
                entry(10, 1, None, "/app/client"),
                entry(20, 2, Some(10), "/browser/shared"),
            ]
            .into(),
        );
        tree.expand(
            &[
                entry(20, 2, None, "/browser/shared"),
                entry(30, 3, Some(20), "/helpers/worker"),
                entry(99, 4, None, "/browser/shared"),
            ]
            .into(),
        );
        assert!(tree.known.contains(&ProcessIdentity {
            pid: 30,
            start_time: 3
        }));
        assert!(!tree.known.iter().any(|p| p.pid == 99));
    }
    #[test]
    fn resolves_selected_image_before_capture() {
        let selection =
            ProcessSelection::from_pids(&[std::process::id(), std::process::id()]).unwrap();
        assert_eq!(selection.processes().len(), 1);
        assert_eq!(selection.images().len(), 1);
        assert!(same_image(
            &selection.images()[0],
            &std::env::current_exe().unwrap().canonicalize().unwrap()
        ));
    }
    #[test]
    fn platform_path_matching() {
        assert!(!same_image(
            Path::new("/one/client"),
            Path::new("/two/client")
        ));
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("client");
        std::fs::write(&path, b"image").unwrap();
        let alias = directory.path().join("alias");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(same_image(&path, &alias));
        let other = directory.path().join("other");
        std::fs::write(&other, b"image").unwrap();
        assert!(!same_image(&path, &other));
    }
}
