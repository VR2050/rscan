use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use goblin::Object;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::errors::RustpenError;

use super::model::{
    ApkReport, BinaryFormat, BinaryReport, FileHashes, HardeningReport, SecuritySignals,
};
use super::rules::RuleLibrary;

pub struct ReverseAnalyzer;

impl ReverseAnalyzer {
    pub fn analyze_binary(path: &Path) -> Result<BinaryReport, RustpenError> {
        Self::analyze_binary_with_rules(path, &RuleLibrary::default())
    }

    pub fn analyze_binary_with_rules(
        path: &Path,
        rules: &RuleLibrary,
    ) -> Result<BinaryReport, RustpenError> {
        let bytes = std::fs::read(path)?;
        let md = std::fs::metadata(path)?;
        let format = detect_format(&bytes);

        let mut architecture = None;
        let mut entry_point = None;
        let mut sections = Vec::new();
        let mut imports = Vec::new();
        let mut hardening = HardeningReport {
            nx: None,
            pie_or_aslr: None,
            relro: None,
            stack_canary: None,
        };

        if matches!(format, BinaryFormat::Elf | BinaryFormat::Pe) {
            match Object::parse(&bytes) {
                Ok(Object::Elf(elf)) => {
                    architecture = Some(format!("{:?}", elf.header.e_machine));
                    entry_point = Some(elf.entry);
                    sections = elf
                        .section_headers
                        .iter()
                        .filter_map(|s| elf.shdr_strtab.get_at(s.sh_name))
                        .map(str::to_string)
                        .collect();
                    imports = elf
                        .dynsyms
                        .iter()
                        .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();

                    let has_gnu_relro = elf
                        .program_headers
                        .iter()
                        .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO);
                    let has_bind_now = elf.dynamic.as_ref().is_some_and(|d| {
                        d.dyns
                            .iter()
                            .any(|x| x.d_tag == goblin::elf::dynamic::DT_BIND_NOW)
                    });
                    let gnu_stack_non_exec = elf
                        .program_headers
                        .iter()
                        .find(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_STACK)
                        .is_some_and(|stack| {
                            (stack.p_flags & goblin::elf::program_header::PF_X) == 0
                        });

                    hardening.nx = Some(gnu_stack_non_exec);
                    hardening.pie_or_aslr = Some(elf.header.e_type == goblin::elf::header::ET_DYN);
                    hardening.relro = Some(has_gnu_relro);
                    hardening.stack_canary =
                        Some(imports.iter().any(|i| i.contains("__stack_chk_fail")));

                    if has_bind_now {
                        hardening.relro = Some(true);
                    }
                }
                Ok(Object::PE(pe)) => {
                    architecture = Some(format!("0x{:x}", pe.header.coff_header.machine));
                    if let Some(optional) = pe.header.optional_header {
                        entry_point = Some(optional.standard_fields.address_of_entry_point as u64);
                        let dll_char = optional.windows_fields.dll_characteristics;
                        // 0x0100: NX_COMPAT, 0x0040: DYNAMIC_BASE
                        hardening.nx = Some((dll_char & 0x0100) != 0);
                        hardening.pie_or_aslr = Some((dll_char & 0x0040) != 0);
                    }

                    sections = pe
                        .sections
                        .iter()
                        .map(|s| s.name().unwrap_or("<invalid>").to_string())
                        .collect();

                    imports = pe
                        .imports
                        .iter()
                        .map(|i| format!("{}!{}", i.dll, i.name))
                        .collect();
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(RustpenError::ParseError(format!(
                        "unable to parse binary object '{}': {}",
                        path.display(),
                        e
                    )));
                }
            }
        }

        let entropy = shannon_entropy(&bytes);
        let strings = extract_ascii_strings(&bytes, 4, 4096);

        let anti_debug = find_keywords(&imports, &strings, &rules.anti_debug_keywords);
        let suspicious_strings = find_string_keywords(&strings, &rules.suspicious_string_keywords);
        let suspicious_imports = find_import_keywords(&imports, &rules.suspicious_import_keywords);
        let packer_indicators = packer_hints(
            &sections,
            &strings,
            entropy,
            imports.len(),
            &rules.packer_section_names,
            &rules.packer_string_keywords,
            rules.thresholds.high_entropy,
            rules.thresholds.tiny_import_table_max,
        );

        let malware_score = compute_malware_score(
            entropy,
            anti_debug.len(),
            suspicious_imports.len(),
            suspicious_strings.len(),
            packer_indicators.len(),
            rules.thresholds.high_entropy,
        );

        Ok(BinaryReport {
            path: path.to_path_buf(),
            format,
            architecture,
            entry_point,
            file_size: md.len(),
            hashes: FileHashes {
                sha256: sha256_hex(&bytes),
            },
            sections,
            imports,
            hardening,
            security: SecuritySignals {
                anti_debug_indicators: anti_debug,
                packer_indicators,
                suspicious_imports,
                suspicious_strings,
                entropy,
                malware_score,
            },
        })
    }

    pub fn analyze_apk(path: &Path) -> Result<ApkReport, RustpenError> {
        Self::analyze_apk_with_rules(path, &RuleLibrary::default())
    }

    pub fn analyze_apk_with_rules(
        path: &Path,
        rules: &RuleLibrary,
    ) -> Result<ApkReport, RustpenError> {
        let bytes = std::fs::read(path)?;
        let md = std::fs::metadata(path)?;
        if !matches!(detect_format(&bytes), BinaryFormat::Apk) {
            return Err(RustpenError::ParseError(format!(
                "{} is not recognized as an APK",
                path.display()
            )));
        }

        let mut file = File::open(path)?;
        let mut zip_data = Vec::new();
        file.read_to_end(&mut zip_data)?;
        let cursor = std::io::Cursor::new(zip_data);
        let mut zip = ZipArchive::new(cursor)
            .map_err(|e| RustpenError::ParseError(format!("invalid APK zip: {}", e)))?;

        let mut entries = Vec::new();
        let mut has_manifest = false;
        let mut has_classes_dex = false;
        let mut native_libs = Vec::new();

        for i in 0..zip.len() {
            let file = zip
                .by_index(i)
                .map_err(|e| RustpenError::ParseError(format!("zip entry read failed: {}", e)))?;
            let name = file.name().to_string();
            if name == "AndroidManifest.xml" {
                has_manifest = true;
            }
            if name == "classes.dex" || name.starts_with("classes") && name.ends_with(".dex") {
                has_classes_dex = true;
            }
            if name.starts_with("lib/") && name.ends_with(".so") {
                native_libs.push(name.clone());
            }
            entries.push(name);
        }

        let entropy = shannon_entropy(&bytes);
        let strings = extract_ascii_strings(&bytes, 4, 4096);
        let suspicious_strings = find_string_keywords(&strings, &rules.suspicious_string_keywords);
        let anti_debug = find_string_keywords(&strings, &rules.anti_debug_keywords);
        let mut packer_indicators = find_string_keywords(&strings, &rules.packer_string_keywords)
            .into_iter()
            .map(|s| format!("packer string: {}", s))
            .collect::<Vec<_>>();

        if entropy > rules.thresholds.apk_high_entropy {
            packer_indicators.push(format!("apk entropy is high {:.3}", entropy));
        }
        if entries.iter().any(|e| e.contains("/assets/")) && !has_classes_dex {
            packer_indicators.push("missing classes.dex but has assets tree".to_string());
        }

        packer_indicators.sort();
        packer_indicators.dedup();

        let malware_score = compute_malware_score(
            entropy,
            anti_debug.len(),
            0,
            suspicious_strings.len(),
            packer_indicators.len(),
            rules.thresholds.apk_high_entropy,
        );

        Ok(ApkReport {
            path: path.to_path_buf(),
            file_size: md.len(),
            hashes: FileHashes {
                sha256: sha256_hex(&bytes),
            },
            entries,
            has_manifest,
            has_classes_dex,
            has_native_libs: !native_libs.is_empty(),
            native_libs,
            security: SecuritySignals {
                anti_debug_indicators: anti_debug,
                packer_indicators,
                suspicious_imports: Vec::new(),
                suspicious_strings,
                entropy,
                malware_score,
            },
        })
    }
}

pub fn detect_format(bytes: &[u8]) -> BinaryFormat {
    if bytes.len() >= 4 && bytes[0..4] == [0x7f, b'E', b'L', b'F'] {
        return BinaryFormat::Elf;
    }

    if bytes.len() >= 0x40 && &bytes[0..2] == b"MZ" {
        let pe_offset =
            u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
        if bytes.len() >= pe_offset + 4 && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0" {
            return BinaryFormat::Pe;
        }
    }

    if bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04" {
        let manifest = bytes
            .windows("AndroidManifest.xml".len())
            .any(|w| w == b"AndroidManifest.xml");
        let classes = bytes
            .windows("classes.dex".len())
            .any(|w| w == b"classes.dex");
        if manifest || classes {
            return BinaryFormat::Apk;
        }
    }

    BinaryFormat::Unknown
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn extract_ascii_strings(bytes: &[u8], min_len: usize, max_items: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();

    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                out.push(String::from_utf8_lossy(&current).to_string());
                if out.len() >= max_items {
                    break;
                }
            }
            current.clear();
        }
    }

    if out.len() < max_items && current.len() >= min_len {
        out.push(String::from_utf8_lossy(&current).to_string());
    }

    out
}

fn find_keywords(imports: &[String], strings: &[String], keywords: &[String]) -> Vec<String> {
    let mut found = HashSet::new();
    for imp in imports {
        let lower = imp.to_ascii_lowercase();
        for key in keywords {
            if lower.contains(&key.to_ascii_lowercase()) {
                found.insert(format!("import:{}", key));
            }
        }
    }
    for s in strings {
        let lower = s.to_ascii_lowercase();
        for key in keywords {
            if lower.contains(&key.to_ascii_lowercase()) {
                found.insert(format!("string:{}", key));
            }
        }
    }

    let mut v: Vec<String> = found.into_iter().collect();
    v.sort();
    v
}

fn find_import_keywords(imports: &[String], keywords: &[String]) -> Vec<String> {
    let mut out = HashSet::new();
    for imp in imports {
        let lower = imp.to_ascii_lowercase();
        for key in keywords {
            if lower.contains(&key.to_ascii_lowercase()) {
                out.insert(imp.clone());
            }
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v
}

fn find_string_keywords(strings: &[String], keywords: &[String]) -> Vec<String> {
    let mut out = HashSet::new();
    for s in strings {
        let lower = s.to_ascii_lowercase();
        for key in keywords {
            if lower.contains(&key.to_ascii_lowercase()) {
                out.insert(s.clone());
            }
        }
    }
    let mut v: Vec<String> = out.into_iter().collect();
    v.sort();
    v
}

fn packer_hints(
    sections: &[String],
    strings: &[String],
    entropy: f64,
    import_count: usize,
    known_packer_sections: &[String],
    packer_strings: &[String],
    high_entropy_threshold: f64,
    tiny_import_table_max: usize,
) -> Vec<String> {
    let mut hints = Vec::new();

    for sec in sections {
        for known in known_packer_sections {
            if sec.eq_ignore_ascii_case(known) {
                hints.push(format!("packed section name: {}", sec));
            }
        }
    }

    for string_hit in find_string_keywords(strings, packer_strings) {
        hints.push(format!("packer string: {}", string_hit));
    }

    if entropy > high_entropy_threshold {
        hints.push(format!("high entropy {:.3}", entropy));
    }

    if import_count > 0 && import_count <= tiny_import_table_max {
        hints.push("very small import table".to_string());
    }

    hints.sort();
    hints.dedup();
    hints
}

fn compute_malware_score(
    entropy: f64,
    anti_debug_hits: usize,
    suspicious_imports: usize,
    suspicious_strings: usize,
    packer_hits: usize,
    high_entropy_threshold: f64,
) -> u8 {
    let mut score = 0.0f64;
    if entropy > high_entropy_threshold {
        score += 25.0;
    }
    score += (anti_debug_hits as f64 * 8.0).min(24.0);
    score += (suspicious_imports as f64 * 5.0).min(20.0);
    score += (suspicious_strings as f64 * 2.5).min(15.0);
    score += (packer_hits as f64 * 10.0).min(30.0);

    score.clamp(0.0, 100.0) as u8
}

#[cfg(test)]
mod tests {
    use super::ReverseAnalyzer;
    use crate::modules::reverse::{BinaryFormat, RuleLibrary};
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn analyze_local_elf_binary() {
        let candidate = if std::path::Path::new("/bin/ls").exists() {
            "/bin/ls"
        } else {
            "/usr/bin/ls"
        };
        if !std::path::Path::new(candidate).exists() {
            return;
        }

        let report = ReverseAnalyzer::analyze_binary(std::path::Path::new(candidate)).unwrap();
        assert!(matches!(report.format, BinaryFormat::Elf));
        assert!(report.file_size > 0);
        assert!(!report.hashes.sha256.is_empty());
    }

    #[test]
    fn analyze_minimal_apk_zip() {
        let tmp = std::env::temp_dir().join("rscan_reverse_test.apk");
        let f = File::create(&tmp).unwrap();
        let mut zip = zip::ZipWriter::new(f);
        let options = zip::write::FileOptions::default();
        zip.start_file("AndroidManifest.xml", options).unwrap();
        zip.write_all(b"manifest").unwrap();
        zip.start_file("classes.dex", options).unwrap();
        zip.write_all(b"dex").unwrap();
        zip.finish().unwrap();

        let report = ReverseAnalyzer::analyze_apk(&tmp).unwrap();
        assert!(report.has_manifest);
        assert!(report.has_classes_dex);
        assert_eq!(report.path, tmp);

        let _ = std::fs::remove_file(report.path);
    }

    #[test]
    fn custom_rules_apply() {
        let candidate = if std::path::Path::new("/bin/ls").exists() {
            "/bin/ls"
        } else {
            "/usr/bin/ls"
        };
        if !std::path::Path::new(candidate).exists() {
            return;
        }

        let mut rules = RuleLibrary::default();
        rules.suspicious_import_keywords = vec!["printf".to_string()];
        let report =
            ReverseAnalyzer::analyze_binary_with_rules(std::path::Path::new(candidate), &rules)
                .unwrap();
        assert!(report.file_size > 0);
    }
}
