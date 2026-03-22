use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::modules::reverse::ReverseJobMeta;
use crate::tui::reverse_workbench_support::{active_target_hint_path, canonical_or_clone};

const TAIL_READ_CHUNK: usize = 16 * 1024;
const MAX_TAIL_SCAN_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeckTargetRevision {
    pub(super) path: PathBuf,
    pub(super) hint_write_ns: u128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ReverseArtifactSummary {
    pub(super) functions: usize,
    pub(super) pseudocode_rows: usize,
    pub(super) asm_rows: usize,
    pub(super) cfg_rows: usize,
    pub(super) strings_rows: usize,
    pub(super) calls_rows: usize,
    pub(super) xrefs_rows: usize,
    pub(super) recovered_prologues: Option<usize>,
}

pub(super) fn target_revision(root_ws: &Path, target: &Path) -> DeckTargetRevision {
    let hint_write_ns = fs::metadata(active_target_hint_path(root_ws))
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    DeckTargetRevision {
        path: canonical_or_clone(target),
        hint_write_ns,
    }
}

pub(super) fn read_last_lines_fast(path: &Path, limit: usize) -> Vec<String> {
    if limit == 0 || !path.is_file() {
        return Vec::new();
    }
    let Some((bytes, partial_first_line)) = read_tail_bytes(path, limit) else {
        return Vec::new();
    };
    if bytes.is_empty() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    if partial_first_line && !lines.is_empty() {
        lines.remove(0);
    }
    if lines.len() > limit {
        lines.drain(..lines.len() - limit);
    }
    lines
}

fn read_tail_bytes(path: &Path, line_hint: usize) -> Option<(Vec<u8>, bool)> {
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len == 0 {
        return Some((Vec::new(), false));
    }

    let mut remaining = file_len;
    let mut scanned = 0usize;
    let mut newline_count = 0usize;
    let target_newlines = line_hint.saturating_add(1);
    let mut chunks = Vec::new();

    while remaining > 0 && scanned < MAX_TAIL_SCAN_BYTES && newline_count < target_newlines {
        let chunk_len = TAIL_READ_CHUNK.min(remaining as usize);
        remaining -= chunk_len as u64;
        file.seek(SeekFrom::Start(remaining)).ok()?;
        let mut chunk = vec![0_u8; chunk_len];
        file.read_exact(&mut chunk).ok()?;
        newline_count += chunk.iter().filter(|byte| **byte == b'\n').count();
        scanned += chunk_len;
        chunks.push(chunk);
    }

    chunks.reverse();
    let total_len = chunks.iter().map(Vec::len).sum();
    let mut bytes = Vec::with_capacity(total_len);
    for chunk in chunks {
        bytes.extend_from_slice(&chunk);
    }

    let partial_first_line = if remaining == 0 {
        false
    } else {
        let mut prev = [0_u8; 1];
        file.seek(SeekFrom::Start(remaining - 1)).ok()?;
        file.read_exact(&mut prev).ok()?;
        prev[0] != b'\n'
    };

    Some((bytes, partial_first_line))
}

pub(super) fn load_job_artifact_summary(job: &ReverseJobMeta) -> ReverseArtifactSummary {
    let out_dir = job.workspace.join("reverse_out").join(&job.id);
    let stdout_log = job.workspace.join("jobs").join(&job.id).join("stdout.log");
    ReverseArtifactSummary {
        functions: count_jsonl_rows(&out_dir.join("index.jsonl")),
        pseudocode_rows: count_jsonl_rows(&find_artifact_path(
            job,
            &["pseudocode.jsonl", "function.jsonl"],
            out_dir.join("pseudocode.jsonl"),
        )),
        asm_rows: count_jsonl_rows(&out_dir.join("asm_functions.jsonl")),
        cfg_rows: count_jsonl_rows(&out_dir.join("cfg_functions.jsonl")),
        strings_rows: count_jsonl_rows(&out_dir.join("strings_functions.jsonl")),
        calls_rows: count_jsonl_rows(&out_dir.join("calls_functions.jsonl")),
        xrefs_rows: count_jsonl_rows(&out_dir.join("xrefs_functions.jsonl")),
        recovered_prologues: parse_recovered_prologues(&stdout_log),
    }
}

fn normalize_artifact_path(job: &ReverseJobMeta, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        job.workspace.join(path)
    }
}

fn find_artifact_path(job: &ReverseJobMeta, suffixes: &[&str], fallback: PathBuf) -> PathBuf {
    for artifact in &job.artifacts {
        if suffixes.iter().any(|suffix| artifact.ends_with(suffix)) {
            let candidate = normalize_artifact_path(job, artifact);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    fallback
}

fn count_jsonl_rows(path: &Path) -> usize {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.lines().filter(|line| !line.trim().is_empty()).count())
        .unwrap_or(0)
}

fn parse_recovered_prologues(path: &Path) -> Option<usize> {
    let text = fs::read_to_string(path).ok()?;
    for segment in text.split_whitespace() {
        let Some(value) = segment.strip_prefix("recovered_prologues=") else {
            continue;
        };
        if let Ok(parsed) = value.parse::<usize>() {
            return Some(parsed);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::reverse::ReverseJobStatus;

    fn temp_path(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("rscan_reverse_deck_{name}_{stamp:x}.log"))
    }

    #[test]
    fn read_last_lines_fast_returns_tail_only() {
        let path = temp_path("tail");
        let body = (0..200)
            .map(|idx| format!("line-{idx:03}"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&path, body).unwrap();

        let lines = read_last_lines_fast(&path, 4);
        assert_eq!(lines, vec!["line-196", "line-197", "line-198", "line-199"]);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn read_last_lines_fast_returns_empty_for_missing_file() {
        let path = temp_path("missing");
        assert!(read_last_lines_fast(&path, 8).is_empty());
    }

    #[test]
    fn load_job_artifact_summary_reads_counts_and_recovery_marker() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let ws = std::env::temp_dir().join(format!("rscan_reverse_summary_{stamp:x}"));
        let out_dir = ws.join("reverse_out").join("job-test");
        let job_dir = ws.join("jobs").join("job-test");
        fs::create_dir_all(&out_dir).unwrap();
        fs::create_dir_all(&job_dir).unwrap();
        fs::write(
            out_dir.join("index.jsonl"),
            "{\"ea\":\"0x1\"}\n{\"ea\":\"0x2\"}\n",
        )
        .unwrap();
        fs::write(out_dir.join("asm_functions.jsonl"), "{\"func\":\"0x1\"}\n").unwrap();
        fs::write(out_dir.join("cfg_functions.jsonl"), "{\"func\":\"0x1\"}\n").unwrap();
        fs::write(
            out_dir.join("strings_functions.jsonl"),
            "{\"func\":\"0x1\"}\n{\"func\":\"0x2\"}\n",
        )
        .unwrap();
        fs::write(
            out_dir.join("calls_functions.jsonl"),
            "{\"func\":\"0x1\"}\n",
        )
        .unwrap();
        fs::write(
            out_dir.join("xrefs_functions.jsonl"),
            "{\"func\":\"0x1\"}\n",
        )
        .unwrap();
        fs::write(out_dir.join("pseudocode.jsonl"), "{\"ea\":\"0x1\"}\n").unwrap();
        fs::write(
            job_dir.join("stdout.log"),
            "rust index arch=X86_64 funcs=2 recovered_prologues=3 asm=10\n",
        )
        .unwrap();

        let job = ReverseJobMeta {
            id: "job-test".to_string(),
            kind: "decompile".to_string(),
            backend: "rust-index".to_string(),
            mode: Some("index".to_string()),
            function: None,
            target: ws.join("sample.bin"),
            workspace: ws.clone(),
            status: ReverseJobStatus::Succeeded,
            created_at: 0,
            started_at: None,
            ended_at: None,
            exit_code: Some(0),
            program: "rust-index".to_string(),
            args: Vec::new(),
            note: String::new(),
            artifacts: vec![out_dir.join("pseudocode.jsonl").display().to_string()],
            error: None,
        };

        let summary = load_job_artifact_summary(&job);
        assert_eq!(summary.functions, 2);
        assert_eq!(summary.pseudocode_rows, 1);
        assert_eq!(summary.asm_rows, 1);
        assert_eq!(summary.cfg_rows, 1);
        assert_eq!(summary.strings_rows, 2);
        assert_eq!(summary.calls_rows, 1);
        assert_eq!(summary.xrefs_rows, 1);
        assert_eq!(summary.recovered_prologues, Some(3));

        let _ = fs::remove_dir_all(ws);
    }
}
