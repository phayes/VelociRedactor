//! Telling people why the mount refused something: the `user.veloci.status`
//! attribute, the log, and the `--status-dir` file.

use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use super::policy::Reason;
use super::view::{Class, View};

/// The extended attribute every file carries through the mount.
pub const STATUS_XATTR: &str = "user.veloci.status";

/// Refusals the status file keeps.
const RECENT: usize = 200;

/// The value of [`STATUS_XATTR`] for a regular file. Never holds a value.
pub fn file_status(view: Option<&View>, config: bool) -> String {
    let mut text = match view.map(|v| &v.class) {
        None => "unreadable".to_owned(),
        Some(Class::Excluded) => "excluded (allow.files)".to_owned(),
        Some(Class::Clean) => "clean".to_owned(),
        Some(Class::Binary) => "binary".to_owned(),
        Some(Class::Failed(err)) => format!("failed: {err}; reads and writes denied"),
        Some(Class::Redacted) => {
            let view = view.expect("matched Some");
            let n = view.redacted();
            let detectors: Vec<&str> = view.findings.keys().map(String::as_str).collect();
            format!(
                "redacted: {n} {} ({}); writes denied",
                if n == 1 { "finding" } else { "findings" },
                detectors.join(", ")
            )
        }
    };
    if config {
        text.push_str("; configuration file, writes denied");
    }
    text
}

/// Where refusals are reported.
pub struct DenialLog {
    sink: Mutex<Box<dyn Write + Send>>,
    recent: Mutex<VecDeque<String>>,
}

impl DenialLog {
    pub fn new(sink: Box<dyn Write + Send>) -> Self {
        DenialLog {
            sink: Mutex::new(sink),
            recent: Mutex::new(VecDeque::new()),
        }
    }

    /// Report that process `pid` was refused `op` on `path`.
    pub fn deny(&self, pid: u32, op: &str, path: &Path, reason: &Reason) {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|c| c.trim_end().to_owned())
            .unwrap_or_default();
        let line = format!(
            "veloci: denied {op} {} (pid {pid}, {comm:?}): {reason}",
            path.display()
        );
        {
            let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(sink, "{line}");
            let _ = sink.flush();
        }
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        if recent.len() == RECENT {
            recent.pop_front();
        }
        recent.push_back(line);
    }

    /// The recent refusals, one per line, oldest first.
    pub fn recent(&self) -> Vec<u8> {
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = String::new();
        for line in recent.iter() {
            text.push_str(line);
            text.push('\n');
        }
        text.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn status_text() {
        let mut findings = BTreeMap::new();
        findings.insert("credentialed_uri".to_owned(), 1);
        findings.insert("entropy".to_owned(), 1);
        let view = View {
            class: Class::Redacted,
            size: 0,
            bytes: Some(Arc::from(&b""[..])),
            findings,
        };
        assert_eq!(
            file_status(Some(&view), false),
            "redacted: 2 findings (credentialed_uri, entropy); writes denied"
        );
        let clean = View {
            class: Class::Clean,
            size: 0,
            bytes: None,
            findings: BTreeMap::new(),
        };
        assert_eq!(
            file_status(Some(&clean), true),
            "clean; configuration file, writes denied"
        );
    }

    #[test]
    fn log_keeps_recent_lines() {
        let log = DenialLog::new(Box::new(std::io::sink()));
        log.deny(0, "write to", Path::new(".env"), &Reason::Redacted(2));
        let text = String::from_utf8(log.recent()).unwrap();
        assert!(text.starts_with("veloci: denied write to .env (pid 0"));
        assert!(text.ends_with("it holds 2 redacted secrets\n"));
    }
}
