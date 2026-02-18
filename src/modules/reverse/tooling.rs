use std::path::{Path, PathBuf};

use crate::errors::RustpenError;

use super::model::{DebugProfile, DecompilerEngine, ToolInvocation};

pub struct ReverseTooling;

impl ReverseTooling {
    pub fn build_decompile_invocation(
        engine: DecompilerEngine,
        input: &Path,
        output_dir: Option<&Path>,
    ) -> ToolInvocation {
        match engine {
            DecompilerEngine::Objdump => ToolInvocation {
                program: "objdump".to_string(),
                args: vec![
                    "-d".to_string(),
                    "-M".to_string(),
                    "intel".to_string(),
                    input.display().to_string(),
                ],
                note: "Basic linear disassembly for ELF/PE. Fast and scriptable.".to_string(),
            },
            DecompilerEngine::Radare2 => ToolInvocation {
                program: "r2".to_string(),
                args: vec!["-A".to_string(), input.display().to_string()],
                note: "Radare2 analysis mode; use r2pipe/cutter for deeper workflows.".to_string(),
            },
            DecompilerEngine::Ghidra => {
                let out = output_dir
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("./ghidra_out"));
                let script_name = "ghidra_export_pseudocode.java";
                ToolInvocation {
                    program: "analyzeHeadless".to_string(),
                    args: vec![
                        out.display().to_string(),
                        "rscan_project".to_string(),
                        "-import".to_string(),
                        input.display().to_string(),
                        "-scriptPath".to_string(),
                        out.display().to_string(),
                        "-postScript".to_string(),
                        script_name.to_string(),
                        "pseudocode.jsonl".to_string(),
                    ],
                    note: "Headless Ghidra decompile pipeline. Generate script via `rscan reverse ghidra-script --out <dir>/ghidra_export_pseudocode.java` first.".to_string(),
                }
            }
            DecompilerEngine::Ida => {
                let out = output_dir
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("./ida_pseudo"));
                let script = out.join("ida_export_pseudocode.py");
                ToolInvocation {
                    program: "idat64".to_string(),
                    args: vec![
                        "-A".to_string(),
                        format!("-S{} {}", script.display(), out.display()),
                        input.display().to_string(),
                    ],
                    note: "IDA batch with IDAPython script for function-level pseudocode export. Needs Hex-Rays availability."
                        .to_string(),
                }
            }
            DecompilerEngine::Jadx => {
                let out = output_dir
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("./jadx_out"));
                ToolInvocation {
                    program: "jadx".to_string(),
                    args: vec![
                        "-d".to_string(),
                        out.display().to_string(),
                        input.display().to_string(),
                    ],
                    note: "APK decompilation (Java/Kotlin + resources).".to_string(),
                }
            }
        }
    }

    pub fn generate_debug_script(profile: DebugProfile, target: &Path) -> String {
        match profile {
            DebugProfile::PwnGdbLike => pwngdb_like_script(target),
            DebugProfile::PwndbgCompat => pwndbg_compat_script(target, None),
        }
    }

    pub fn write_debug_script(
        profile: DebugProfile,
        target: &Path,
        output: &Path,
    ) -> Result<(), RustpenError> {
        let script = Self::generate_debug_script(profile, target);
        std::fs::write(output, script)?;
        Ok(())
    }

    pub fn write_debug_script_with_pwndbg(
        profile: DebugProfile,
        target: &Path,
        output: &Path,
        pwndbg_init: Option<&Path>,
    ) -> Result<(), RustpenError> {
        let script = match profile {
            DebugProfile::PwndbgCompat => pwndbg_compat_script(target, pwndbg_init),
            _ => Self::generate_debug_script(profile, target),
        };
        std::fs::write(output, script)?;
        Ok(())
    }

    pub fn generate_gdb_python_plugin() -> String {
        r#"# rscan_gdb_plugin.py
import gdb

class RscanRegs(gdb.Command):
    def __init__(self):
        super(RscanRegs, self).__init__("rscan-regs", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        gdb.execute("info registers")

class RscanStack(gdb.Command):
    def __init__(self):
        super(RscanStack, self).__init__("rscan-stack", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        count = arg.strip() or "32"
        gdb.execute(f"x/{count}gx $sp")

class RscanHeap(gdb.Command):
    def __init__(self):
        super(RscanHeap, self).__init__("rscan-heap", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        try:
            # glibc malloc_info-based best effort via command compatibility
            gdb.execute("heap bins")
        except Exception:
            print("heap bins unavailable; install pwndbg/gef or use glibc-heap helpers")

class RscanSymbols(gdb.Command):
    def __init__(self):
        super(RscanSymbols, self).__init__("rscan-symbols", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        pattern = arg.strip() or "."
        gdb.execute(f"info functions {pattern}")

class RscanContext(gdb.Command):
    def __init__(self):
        super(RscanContext, self).__init__("rscan-context", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        gdb.execute("rscan-regs")
        gdb.execute("rscan-stack 32")
        gdb.execute("x/16i $pc")

RscanRegs()
RscanStack()
RscanHeap()
RscanSymbols()
RscanContext()
print("[rscan] gdb plugin loaded: rscan-regs/rscan-stack/rscan-heap/rscan-symbols/rscan-context")
"#
        .to_string()
    }

    pub fn write_gdb_python_plugin(output: &Path) -> Result<(), RustpenError> {
        std::fs::write(output, Self::generate_gdb_python_plugin())?;
        Ok(())
    }

    pub fn generate_ida_export_script() -> String {
        r#"# ida_export_pseudocode.py
# usage: idat64 -A -S"ida_export_pseudocode.py <out_dir>" <binary>
import os
import json
import ida_auto
import ida_funcs
import ida_hexrays
import idaapi
import idc

def main():
    out_dir = idc.ARGV[1] if len(idc.ARGV) > 1 else "."
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "pseudocode.jsonl")

    ida_auto.auto_wait()
    has_hexrays = ida_hexrays.init_hexrays_plugin()

    with open(out_file, "w", encoding="utf-8") as f:
        for ea in ida_funcs.Functions():
            fn = ida_funcs.get_func(ea)
            if not fn:
                continue
            name = idaapi.get_func_name(ea)
            row = {
                "ea": hex(ea),
                "name": name,
                "pseudocode": None,
                "error": None,
            }
            if has_hexrays:
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        row["pseudocode"] = "\n".join([line.line for line in cfunc.get_pseudocode()])
                except Exception as e:
                    row["error"] = str(e)
            else:
                row["error"] = "hexrays_not_available"
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print("[rscan] pseudocode exported to", out_file)
    idc.qexit(0)

if __name__ == "__main__":
    main()
"#
        .to_string()
    }

    pub fn write_ida_export_script(output: &Path) -> Result<(), RustpenError> {
        std::fs::write(output, Self::generate_ida_export_script())?;
        Ok(())
    }

    pub fn generate_ghidra_export_script() -> String {
        r#"// ghidra_export_pseudocode.java
// @category rscan
// Usage:
// analyzeHeadless <project_dir> <project_name> -import <binary> \
//   -scriptPath <script_dir> -postScript ghidra_export_pseudocode.java pseudocode.jsonl

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class ghidra_export_pseudocode extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String outName = getScriptArgs().length > 0 ? getScriptArgs()[0] : "pseudocode.jsonl";
        File outFile = new File(outName);
        if (!outFile.isAbsolute()) {
            outFile = new File(currentProgram.getExecutablePath()).getParentFile().toPath().resolve(outName).toFile();
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                String body = null;
                String err = null;
                String signature = f.getSignature().getPrototypeString();
                long size = f.getBody().getNumAddresses();
                List<String> calls = collectCalls(f);
                List<String> callNames = collectCallNames(f);
                List<String> extRefs = collectExternalRefs(f);
                try {
                    DecompileResults res = ifc.decompileFunction(f, 30, monitor);
                    if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        body = res.getDecompiledFunction().getC();
                    } else {
                        err = res == null ? "null_result" : res.getErrorMessage();
                    }
                } catch (Exception ex) {
                    err = ex.toString();
                }
                String ea = f.getEntryPoint().toString();
                String name = f.getName();
                String json = "{\"ea\":\"" + esc(ea) + "\",\"name\":\"" + esc(name) + "\",\"pseudocode\":" +
                    (body == null ? "null" : "\"" + esc(body) + "\"") +
                    ",\"signature\":\"" + esc(signature) + "\"" +
                    ",\"size\":" + size +
                    ",\"calls\":" + toJsonArray(calls) +
                    ",\"call_names\":" + toJsonArray(callNames) +
                    ",\"ext_refs\":" + toJsonArray(extRefs) +
                    ",\"error\":" +
                    (err == null ? "null" : "\"" + esc(err) + "\"") + "}";
                pw.println(json);
            }
        }

        println("[rscan] ghidra pseudocode exported: " + outFile.getAbsolutePath());
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private List<String> collectCalls(Function f) {
        Set<String> out = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        FunctionManager fm = currentProgram.getFunctionManager();
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall()) {
                continue;
            }
            Address[] flows = ins.getFlows();
            if (flows == null) {
                continue;
            }
            for (Address a : flows) {
                Function callee = fm.getFunctionAt(a);
                if (callee != null) {
                    out.add(callee.getEntryPoint().toString());
                } else {
                    out.add(a.toString());
                }
            }
        }
        return new ArrayList<>(out);
    }

    private List<String> collectExternalRefs(Function f) {
        Set<String> out = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        FunctionManager fm = currentProgram.getFunctionManager();
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall()) {
                continue;
            }
            Address[] flows = ins.getFlows();
            if (flows == null) {
                continue;
            }
            for (Address a : flows) {
                Function callee = fm.getFunctionAt(a);
                if (callee != null && callee.isExternal()) {
                    out.add(callee.getName());
                }
            }
        }
        return new ArrayList<>(out);
    }

    private List<String> collectCallNames(Function f) {
        Set<String> out = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        FunctionManager fm = currentProgram.getFunctionManager();
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall()) {
                continue;
            }
            Address[] flows = ins.getFlows();
            if (flows == null) {
                continue;
            }
            for (Address a : flows) {
                Function callee = fm.getFunctionAt(a);
                if (callee != null) {
                    out.add(callee.getName());
                } else {
                    out.add(a.toString());
                }
            }
        }
        return new ArrayList<>(out);
    }

    private String toJsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(esc(items.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }
}
"#
        .to_string()
    }

    pub fn write_ghidra_export_script(output: &Path) -> Result<(), RustpenError> {
        std::fs::write(output, Self::generate_ghidra_export_script())?;
        Ok(())
    }

    pub fn generate_ghidra_index_script() -> String {
        r#"// ghidra_export_index.java
// @category rscan
// Usage:
// analyzeHeadless <project_dir> <project_name> -import <binary> \
//   -scriptPath <script_dir> -postScript ghidra_export_index.java index.jsonl

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class ghidra_export_index extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String outName = getScriptArgs().length > 0 ? getScriptArgs()[0] : "index.jsonl";
        File outFile = new File(outName);
        if (!outFile.isAbsolute()) {
            outFile = new File(currentProgram.getExecutablePath()).getParentFile().toPath().resolve(outName).toFile();
        }

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                String ea = f.getEntryPoint().toString();
                String name = f.getName();
                String signature = f.getSignature().getPrototypeString();
                long size = f.getBody().getNumAddresses();
                String json = "{\"ea\":\"" + esc(ea) + "\",\"name\":\"" + esc(name) + "\",\"signature\":\"" +
                    esc(signature) + "\",\"size\":" + size + "}";
                pw.println(json);
            }

        }

        println("[rscan] ghidra index exported: " + outFile.getAbsolutePath());
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
"#
        .to_string()
    }

    pub fn write_ghidra_index_script(output: &Path) -> Result<(), RustpenError> {
        std::fs::write(output, Self::generate_ghidra_index_script())?;
        Ok(())
    }

    pub fn generate_ghidra_function_script() -> String {
        r#"// ghidra_export_function.java
// @category rscan
// Usage:
// analyzeHeadless <project_dir> <project_name> -import <binary> \
//   -scriptPath <script_dir> -postScript ghidra_export_function.java function.jsonl <name_or_ea>

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ghidra_export_function extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String outName = getScriptArgs().length > 0 ? getScriptArgs()[0] : "function.jsonl";
        String target = getScriptArgs().length > 1 ? getScriptArgs()[1] : null;
        if (target == null || target.isEmpty()) {
            println("[rscan] missing function name/address argument");
            return;
        }

        File outFile = new File(outName);
        if (!outFile.isAbsolute()) {
            outFile = new File(currentProgram.getExecutablePath()).getParentFile().toPath().resolve(outName).toFile();
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Function f = getFunction(target);
        if (f == null) {
            Address addr = toAddr(target);
            if (addr != null) {
                f = fm.getFunctionAt(addr);
            }
        }

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            if (f == null) {
                pw.println("{\"error\":\"function_not_found\",\"target\":\"" + esc(target) + "\"}");
                println("[rscan] function not found: " + target);
                return;
            }

            DecompInterface ifc = new DecompInterface();
            ifc.openProgram(currentProgram);
            String body = null;
            String err = null;
            try {
                DecompileResults res = ifc.decompileFunction(f, 30, monitor);
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    body = res.getDecompiledFunction().getC();
                } else {
                    err = res == null ? "null_result" : res.getErrorMessage();
                }
            } catch (Exception ex) {
                err = ex.toString();
            }
            String ea = f.getEntryPoint().toString();
            String name = f.getName();
            String signature = f.getSignature().getPrototypeString();
            long size = f.getBody().getNumAddresses();
            String json = "{\"ea\":\"" + esc(ea) + "\",\"name\":\"" + esc(name) +
                "\",\"pseudocode\":" + (body == null ? "null" : "\"" + esc(body) + "\"") +
                ",\"signature\":\"" + esc(signature) + "\"" +
                ",\"size\":" + size +
                ",\"error\":" + (err == null ? "null" : "\"" + esc(err) + "\"") + "}";
            pw.println(json);
        }

        println("[rscan] ghidra function exported: " + outFile.getAbsolutePath());
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
"#
        .to_string()
    }

    pub fn write_ghidra_function_script(output: &Path) -> Result<(), RustpenError> {
        std::fs::write(output, Self::generate_ghidra_function_script())?;
        Ok(())
    }
}

fn pwngdb_like_script(target: &Path) -> String {
    format!(
        "set pagination off
set disassembly-flavor intel
set confirm off
file {target}

python
import sys
print('[rscan] use source /path/to/rscan_gdb_plugin.py to load plugin commands')
end

# lightweight pwngdb-like helpers
define context_regs
  info registers
end

define context_stack
  x/32gx $sp
end

define context_code
  x/16i $pc
end

define context_all
  context_regs
  context_stack
  context_code
end

# common breakpoints
break main
run
",
        target = target.display()
    )
}

fn pwndbg_compat_script(target: &Path, pwndbg_init: Option<&Path>) -> String {
    let source_line = pwndbg_init
        .map(|p| format!("source {}\n", p.display()))
        .unwrap_or_default();
    format!(
        "set pagination off
set disassembly-flavor intel
set confirm off
{source_line}file {target}

python
import gdb
def _rscan_try(cmd):
    try:
        gdb.execute(cmd)
    except Exception as e:
        gdb.write('[rscan] skip %s: %s\\n' % (cmd, e))
end

define rscan-context
  python _rscan_try('context')
  python _rscan_try('telescope $sp 16')
  python _rscan_try('vmmap')
  x/16i $pc
end

define rscan-heap
  python _rscan_try('heap')
  python _rscan_try('bins')
end

define rscan-symbols
  info functions $arg0
end

break main
run
",
        source_line = source_line,
        target = target.display()
    )
}

#[cfg(test)]
mod tests {
    use super::ReverseTooling;

    #[test]
    fn generated_gdb_plugin_has_commands() {
        let s = ReverseTooling::generate_gdb_python_plugin();
        assert!(s.contains("rscan-regs"));
        assert!(s.contains("rscan-stack"));
        assert!(s.contains("rscan-symbols"));
    }

    #[test]
    fn generated_ida_script_exports_jsonl() {
        let s = ReverseTooling::generate_ida_export_script();
        assert!(s.contains("pseudocode.jsonl"));
        assert!(s.contains("ida_hexrays"));
    }

    #[test]
    fn generated_ghidra_script_exports_jsonl() {
        let s = ReverseTooling::generate_ghidra_export_script();
        assert!(s.contains("DecompInterface"));
        assert!(s.contains("pseudocode.jsonl"));
    }

    #[test]
    fn generated_ghidra_index_script_exports_jsonl() {
        let s = ReverseTooling::generate_ghidra_index_script();
        assert!(s.contains("index.jsonl"));
        assert!(s.contains("FunctionManager"));
    }

    #[test]
    fn generated_ghidra_function_script_exports_jsonl() {
        let s = ReverseTooling::generate_ghidra_function_script();
        assert!(s.contains("function.jsonl"));
        assert!(s.contains("decompileFunction"));
    }
}
