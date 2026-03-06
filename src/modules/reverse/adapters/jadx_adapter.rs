use std::fs;
use std::path::{Path, PathBuf};

use crate::errors::RustpenError;
use crate::modules::reverse::adapters::IrAdapter;
use crate::modules::reverse::ir::{IrBinaryMeta, IrFunction, ReverseIrDoc};

#[derive(Debug, Default)]
pub struct JadxIrAdapter;

impl JadxIrAdapter {
    fn collect_source_files(root: &Path, out: &mut Vec<PathBuf>, depth: usize) {
        if depth > 8 {
            return;
        }
        let Ok(rd) = fs::read_dir(root) else {
            return;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                Self::collect_source_files(&p, out, depth + 1);
                continue;
            }
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or_default();
            if ext.eq_ignore_ascii_case("java") || ext.eq_ignore_ascii_case("kt") {
                out.push(p);
            }
        }
    }

    fn source_roots(out_dir: &Path) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        let common = [
            out_dir.join("sources"),
            out_dir.join("src"),
            out_dir.to_path_buf(),
        ];
        for p in common {
            if p.exists() && p.is_dir() {
                roots.push(p);
            }
        }
        roots
    }

    fn relative_name(path: &Path, base: &Path) -> String {
        path.strip_prefix(base)
            .ok()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| path.display().to_string())
    }

    fn parse_methods(source: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in source.lines() {
            let l = line.trim();
            if !l.contains('(') || !l.contains(')') || !l.ends_with('{') {
                continue;
            }
            if l.starts_with("if ")
                || l.starts_with("for ")
                || l.starts_with("while ")
                || l.starts_with("switch ")
                || l.starts_with("catch ")
            {
                continue;
            }
            let prefix = l.split('(').next().unwrap_or_default().trim();
            let name = prefix.split_whitespace().last().unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            out.push(name.to_string());
            if out.len() >= 64 {
                break;
            }
        }
        out
    }
}

impl IrAdapter for JadxIrAdapter {
    fn name(&self) -> &'static str {
        "jadx"
    }

    fn parse_index_row(
        &self,
        _row: &serde_json::Value,
    ) -> Result<Option<IrFunction>, RustpenError> {
        Ok(None)
    }

    fn parse_pseudocode_row(
        &self,
        _row: &serde_json::Value,
    ) -> Result<Option<IrFunction>, RustpenError> {
        Ok(None)
    }

    fn build_doc_with_context(
        &self,
        meta: IrBinaryMeta,
        _index_rows: &[serde_json::Value],
        _pseudocode_rows: &[serde_json::Value],
        out_dir: &Path,
        _target: &Path,
    ) -> Result<ReverseIrDoc, RustpenError> {
        let mut doc = ReverseIrDoc {
            meta,
            ..Default::default()
        };
        let mut files = Vec::new();
        for root in Self::source_roots(out_dir) {
            Self::collect_source_files(&root, &mut files, 0);
        }
        files.sort();
        files.dedup();

        for p in files.into_iter().take(3000) {
            let rel = Self::relative_name(&p, out_dir);
            let Ok(content) = fs::read_to_string(&p) else {
                continue;
            };
            let methods = Self::parse_methods(&content);
            if methods.is_empty() {
                doc.functions.push(IrFunction {
                    ea: format!("jadx::{}", rel),
                    name: rel.clone(),
                    demangled: None,
                    signature: None,
                    size: None,
                    pseudocode: None,
                    asm_preview: None,
                    tags: vec![
                        "jadx".to_string(),
                        "apk".to_string(),
                        "source-file".to_string(),
                    ],
                });
                continue;
            }
            for m in methods {
                doc.functions.push(IrFunction {
                    ea: format!("jadx::{}::{}", rel, m),
                    name: m,
                    demangled: None,
                    signature: None,
                    size: None,
                    pseudocode: None,
                    asm_preview: None,
                    tags: vec!["jadx".to_string(), "apk".to_string(), "method".to_string()],
                });
            }
        }
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::reverse::adapters::IrAdapter;

    #[test]
    fn jadx_adapter_builds_from_sources_tree() {
        let root = std::env::temp_dir().join("rscan_jadx_adapter_test");
        let src_dir = root.join("sources").join("com").join("demo");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("MainActivity.java"),
            "public class MainActivity {\n  public void onCreate(){\n  }\n  private int add(int a,int b){\n    return a+b;\n  }\n}\n",
        )
        .unwrap();

        let adp = JadxIrAdapter;
        let doc = adp
            .build_doc_with_context(
                IrBinaryMeta {
                    sample: "x.apk".to_string(),
                    backend: "jadx".to_string(),
                    format: Some("apk".to_string()),
                    arch: None,
                    entry: None,
                    file_size: None,
                },
                &[],
                &[],
                &root,
                &root.join("x.apk"),
            )
            .unwrap();
        assert!(!doc.functions.is_empty());
        assert!(doc
            .functions
            .iter()
            .any(|f| f.ea.contains("MainActivity.java") && !f.tags.is_empty()));
        let _ = fs::remove_dir_all(&root);
    }
}
