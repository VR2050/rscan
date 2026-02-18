// ghidra_export_pseudocode.java
// @category rscan
// Usage:
// analyzeHeadless <project_dir> <project_name> -import <binary> \
//   -scriptPath <script_dir> -postScript ghidra_export_pseudocode.java pseudocode.jsonl

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

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
                    (body == null ? "null" : "\"" + esc(body) + "\"") + ",\"error\":" +
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
}
