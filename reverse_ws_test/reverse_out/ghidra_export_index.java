// ghidra_export_index.java
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
