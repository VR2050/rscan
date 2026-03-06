use crate::errors::RustpenError;
use crate::modules::reverse::adapters::IrAdapter;
use crate::modules::reverse::ir::IrFunction;

#[derive(Debug, Default)]
pub struct GhidraIrAdapter;

impl GhidraIrAdapter {
    fn string_field(row: &serde_json::Value, key: &str) -> Option<String> {
        row.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
    }
}

impl IrAdapter for GhidraIrAdapter {
    fn name(&self) -> &'static str {
        "ghidra"
    }

    fn parse_index_row(&self, row: &serde_json::Value) -> Result<Option<IrFunction>, RustpenError> {
        let Some(ea) = Self::string_field(row, "ea") else {
            return Ok(None);
        };
        let name = Self::string_field(row, "name").unwrap_or_else(|| "<unnamed>".to_string());
        let size = row.get("size").and_then(|v| v.as_u64());
        let signature = Self::string_field(row, "signature");
        let demangled = Self::string_field(row, "demangled");
        Ok(Some(IrFunction {
            ea,
            name,
            demangled,
            signature,
            size,
            pseudocode: None,
            asm_preview: None,
            tags: Vec::new(),
        }))
    }

    fn parse_pseudocode_row(
        &self,
        row: &serde_json::Value,
    ) -> Result<Option<IrFunction>, RustpenError> {
        let Some(ea) = Self::string_field(row, "ea") else {
            return Ok(None);
        };
        let Some(pseudo) = Self::string_field(row, "pseudocode") else {
            return Ok(None);
        };
        if pseudo.trim().is_empty() {
            return Ok(None);
        }
        let name = Self::string_field(row, "name").unwrap_or_else(|| "<unnamed>".to_string());
        let signature = Self::string_field(row, "signature");
        let demangled = Self::string_field(row, "demangled");
        let size = row.get("size").and_then(|v| v.as_u64());
        Ok(Some(IrFunction {
            ea,
            name,
            demangled,
            signature,
            size,
            pseudocode: Some(pseudo),
            asm_preview: None,
            tags: Vec::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_adapter_parses_index_row() {
        let row = serde_json::json!({
            "ea": "0x401000",
            "name": "main",
            "size": 128,
            "signature": "main()",
            "demangled": "main"
        });
        let adp = GhidraIrAdapter;
        let f = adp.parse_index_row(&row).unwrap().unwrap();
        assert_eq!(f.ea, "0x401000");
        assert_eq!(f.name, "main");
        assert_eq!(f.size, Some(128));
    }

    #[test]
    fn ghidra_adapter_parses_pseudocode_row() {
        let row = serde_json::json!({
            "ea": "0x401000",
            "name": "main",
            "pseudocode": "int main(){return 0;}"
        });
        let adp = GhidraIrAdapter;
        let r = adp.parse_pseudocode_row(&row).unwrap().unwrap();
        assert_eq!(r.ea, "0x401000");
        assert_eq!(r.name, "main");
        assert!(r.pseudocode.unwrap_or_default().contains("main"));
    }
}
