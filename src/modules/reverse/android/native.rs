use std::collections::BTreeSet;

use goblin::Object;

use super::model::NativeLibReport;

pub(crate) fn analyze_native_so(name: &str, bytes: &[u8]) -> NativeLibReport {
    let mut arch = "unknown".to_string();
    let mut imports = BTreeSet::new();
    let mut suspicious_hits = BTreeSet::new();
    let suspicious = [
        "ptrace", "execve", "system", "dlopen", "dlsym", "mprotect", "chmod", "chown", "setuid",
    ];
    if let Ok(obj) = Object::parse(bytes) {
        match obj {
            Object::Elf(elf) => {
                arch = format!("{:?}", elf.header.e_machine);
                for sym in &elf.dynsyms {
                    if let Some(n) = elf.dynstrtab.get_at(sym.st_name)
                        && !n.is_empty()
                    {
                        imports.insert(n.to_string());
                    }
                }
            }
            Object::PE(pe) => {
                arch = format!("0x{:x}", pe.header.coff_header.machine);
                for i in &pe.imports {
                    imports.insert(format!("{}!{}", i.dll, i.name));
                }
            }
            _ => {}
        }
    }
    for i in &imports {
        for s in &suspicious {
            if i.to_ascii_lowercase().contains(s) {
                suspicious_hits.insert(i.to_string());
            }
        }
    }
    NativeLibReport {
        name: name.to_string(),
        size: bytes.len() as u64,
        arch,
        imports_count: imports.len(),
        suspicious_import_hits: suspicious_hits.into_iter().collect(),
    }
}
