use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrBinaryMeta {
    pub sample: String,
    pub backend: String,
    pub format: Option<String>,
    pub arch: Option<String>,
    pub entry: Option<String>,
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrSymbolRef {
    pub ea: String,
    pub name: String,
    pub demangled: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrFunction {
    pub ea: String,
    pub name: String,
    pub demangled: Option<String>,
    pub signature: Option<String>,
    pub size: Option<u64>,
    pub pseudocode: Option<String>,
    pub asm_preview: Option<Vec<String>>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrCallEdge {
    pub caller: String,
    pub callee: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrXrefEdge {
    pub src: String,
    pub dst: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrImport {
    pub name: String,
    pub address: Option<String>,
    pub module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrStringItem {
    pub value: String,
    pub address: Option<String>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrSection {
    pub name: String,
    pub addr: Option<String>,
    pub size: Option<u64>,
    pub flags: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IrRow {
    pub kind: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReverseIrDoc {
    pub meta: IrBinaryMeta,
    pub functions: Vec<IrFunction>,
    pub calls: Vec<IrCallEdge>,
    pub xrefs: Vec<IrXrefEdge>,
    pub imports: Vec<IrImport>,
    pub strings: Vec<IrStringItem>,
    pub sections: Vec<IrSection>,
    pub symbols: Vec<IrSymbolRef>,
    pub findings: Vec<IrRow>,
    pub extra: BTreeMap<String, serde_json::Value>,
}
