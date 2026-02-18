// ghidra_export_function.java
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
