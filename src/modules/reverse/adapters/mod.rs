use std::collections::BTreeMap;
use std::path::Path;

use crate::errors::RustpenError;
use crate::modules::reverse::ir::{IrBinaryMeta, IrFunction, ReverseIrDoc};
use crate::modules::reverse::model::DecompilerEngine;

mod ghidra_adapter;
mod jadx_adapter;

pub use ghidra_adapter::GhidraIrAdapter;
pub use jadx_adapter::JadxIrAdapter;

pub trait IrAdapter: Send + Sync {
    fn name(&self) -> &'static str;

    fn parse_index_row(&self, row: &serde_json::Value) -> Result<Option<IrFunction>, RustpenError>;

    fn parse_pseudocode_row(
        &self,
        row: &serde_json::Value,
    ) -> Result<Option<IrFunction>, RustpenError>;

    fn build_doc_with_context(
        &self,
        meta: IrBinaryMeta,
        index_rows: &[serde_json::Value],
        pseudocode_rows: &[serde_json::Value],
        _out_dir: &Path,
        _target: &Path,
    ) -> Result<ReverseIrDoc, RustpenError> {
        self.build_doc(meta, index_rows, pseudocode_rows)
    }

    fn build_doc(
        &self,
        meta: IrBinaryMeta,
        index_rows: &[serde_json::Value],
        pseudocode_rows: &[serde_json::Value],
    ) -> Result<ReverseIrDoc, RustpenError> {
        let mut doc = ReverseIrDoc {
            meta,
            ..Default::default()
        };
        let mut by_ea: BTreeMap<String, usize> = BTreeMap::new();
        for row in index_rows {
            if let Some(func) = self.parse_index_row(row)? {
                by_ea.insert(func.ea.clone(), doc.functions.len());
                doc.functions.push(func);
            }
        }
        for row in pseudocode_rows {
            if let Some(func) = self.parse_pseudocode_row(row)? {
                if let Some(idx) = by_ea.get(&func.ea).copied() {
                    doc.functions[idx].pseudocode = func.pseudocode;
                    if doc.functions[idx].name == "<unnamed>" && func.name != "<unnamed>" {
                        doc.functions[idx].name = func.name;
                    }
                    if doc.functions[idx].demangled.is_none() {
                        doc.functions[idx].demangled = func.demangled;
                    }
                    if doc.functions[idx].signature.is_none() {
                        doc.functions[idx].signature = func.signature;
                    }
                } else {
                    by_ea.insert(func.ea.clone(), doc.functions.len());
                    doc.functions.push(func);
                }
            }
        }
        Ok(doc)
    }
}

pub fn read_jsonl(path: &Path) -> Result<Vec<serde_json::Value>, RustpenError> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() {
            continue;
        }
        let row = serde_json::from_str::<serde_json::Value>(s).map_err(|e| {
            RustpenError::ParseError(format!(
                "invalid jsonl at {}:{}: {}",
                path.display(),
                i + 1,
                e
            ))
        })?;
        out.push(row);
    }
    Ok(out)
}

pub fn adapter_for_engine(engine: DecompilerEngine) -> Option<Box<dyn IrAdapter>> {
    match engine {
        DecompilerEngine::Ghidra => Some(Box::new(GhidraIrAdapter)),
        DecompilerEngine::Jadx => Some(Box::new(JadxIrAdapter)),
        _ => None,
    }
}
