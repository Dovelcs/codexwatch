use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::RwLock,
};

use anyhow::{Context, Result};
use inotify::{Inotify, WatchMask};
use serde::Deserialize;

const INDEX_FILE_NAME: &str = "session_index.jsonl";

#[derive(Debug, Deserialize)]
struct IndexEntry {
    id: String,
    thread_name: String,
}

#[derive(Debug, Default)]
struct IndexState {
    titles: HashMap<String, String>,
    inode: u64,
    offset: u64,
    partial_line: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct ConversationTitleIndex {
    path: Option<PathBuf>,
    state: RwLock<IndexState>,
}

impl ConversationTitleIndex {
    pub fn open(path: Option<PathBuf>) -> Result<Self> {
        let index = Self {
            path,
            state: RwLock::new(IndexState::default()),
        };
        index.refresh()?;
        Ok(index)
    }

    #[must_use]
    pub fn title(&self, session_id: &str) -> Option<String> {
        self.state.read().ok()?.titles.get(session_id).cloned()
    }

    #[must_use]
    pub fn titles(&self) -> Vec<(String, String)> {
        self.state
            .read()
            .map(|state| {
                state
                    .titles
                    .iter()
                    .map(|(id, title)| (id.clone(), title.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn refresh(&self) -> Result<Vec<(String, String)>> {
        let Some(path) = &self.path else {
            return Ok(Vec::new());
        };
        let metadata = match path.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
        };
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("conversation title index lock poisoned"))?;
        let replaced = state.inode != 0 && state.inode != metadata.ino();
        let truncated = metadata.len() < state.offset;
        if state.inode == 0 || replaced || truncated {
            state.titles.clear();
            state.partial_line.clear();
            state.offset = 0;
        }
        if metadata.len() == state.offset {
            state.inode = metadata.ino();
            return Ok(Vec::new());
        }

        let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        file.seek(SeekFrom::Start(state.offset))?;
        let mut appended = Vec::new();
        file.read_to_end(&mut appended)?;
        state.offset += appended.len() as u64;
        state.inode = metadata.ino();
        state.partial_line.extend_from_slice(&appended);
        Ok(apply_complete_lines(&mut state))
    }

    pub fn watch(
        &self,
        changes: &tokio::sync::mpsc::UnboundedSender<(String, String)>,
    ) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut inotify = Inotify::init().context("initialize inotify")?;
        inotify
            .watches()
            .add(
                parent,
                WatchMask::CREATE
                    | WatchMask::MODIFY
                    | WatchMask::CLOSE_WRITE
                    | WatchMask::MOVED_TO,
            )
            .with_context(|| format!("watch {}", parent.display()))?;
        let mut buffer = [0_u8; 4096];
        loop {
            for event in inotify.read_events_blocking(&mut buffer)? {
                if event.name.and_then(|name| name.to_str()) == Some(INDEX_FILE_NAME) {
                    for change in self.refresh()? {
                        if changes.send(change).is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

fn apply_complete_lines(state: &mut IndexState) -> Vec<(String, String)> {
    let mut changes = Vec::new();
    let complete_bytes = state
        .partial_line
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let complete = state
        .partial_line
        .drain(..complete_bytes)
        .collect::<Vec<_>>();
    for line in complete.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_slice::<IndexEntry>(line)
            && state.titles.get(&entry.id) != Some(&entry.thread_name)
        {
            changes.push((entry.id.clone(), entry.thread_name.clone()));
            state.titles.insert(entry.id, entry.thread_name);
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use super::ConversationTitleIndex;

    #[test]
    fn loads_appends_updates_and_replaced_files() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("session_index.jsonl");
        std::fs::write(&path, b"{\"id\":\"s1\",\"thread_name\":\"first title\"}\n")
            .expect("write index");
        let index = ConversationTitleIndex::open(Some(path.clone())).expect("open index");
        assert_eq!(index.title("s1").as_deref(), Some("first title"));

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append index");
        writeln!(file, "{{\"id\":\"s1\",\"thread_name\":\"renamed\"}}").expect("append title");
        index.refresh().expect("refresh append");
        assert_eq!(index.title("s1").as_deref(), Some("renamed"));

        let replacement = dir.path().join("replacement");
        std::fs::write(
            &replacement,
            b"{\"id\":\"s2\",\"thread_name\":\"replacement title\"}\n",
        )
        .expect("write replacement");
        std::fs::rename(replacement, &path).expect("replace index");
        index.refresh().expect("refresh replacement");
        assert_eq!(index.title("s1"), None);
        assert_eq!(index.title("s2").as_deref(), Some("replacement title"));
    }
}
