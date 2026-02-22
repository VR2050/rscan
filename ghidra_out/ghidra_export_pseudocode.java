// ghidra_export_pseudocode.java
// @category rscan
// Usage:
// analyzeHeadless <project_dir> <project_name> -import <binary> \
//   -scriptPath <script_dir> -postScript ghidra_export_pseudocode.java pseudocode.jsonl

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
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

        if ("1".equals(System.getenv("RSCAN_GHIDRA_SKIP_IF_EXISTS")) && outFile.exists() && outFile.length() > 0) {
            println("[rscan] output exists, skip: " + outFile.getAbsolutePath());
            return;
        }

        int timeoutSec = envInt("RSCAN_GHIDRA_DECOMP_TIMEOUT_SEC", 30);
        boolean incremental = "1".equals(System.getenv("RSCAN_GHIDRA_INCREMENTAL"));
        boolean onlyNamed = "1".equals(System.getenv("RSCAN_GHIDRA_ONLY_NAMED"));
        long maxFuncSize = envLong("RSCAN_GHIDRA_MAX_FUNC_SIZE", -1);
        Set<String> existing = incremental ? loadExistingEas(outFile) : new LinkedHashSet<>();

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        boolean append = incremental && outFile.exists();
        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile, append))) {
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                String ea = f.getEntryPoint().toString();
                if (incremental && existing.contains(ea)) {
                    continue;
                }
                String body = null;
                String err = null;
                String signature = f.getSignature().getPrototypeString();
                long size = f.getBody().getNumAddresses();
                if (maxFuncSize > 0 && size > maxFuncSize) {
                    err = "skipped_large_function";
                }
                String name = f.getName();
                if (onlyNamed && (name.startsWith("FUN_") || name.startsWith("sub_"))) {
                    err = "skipped_unnamed_function";
                }
                List<String> calls = collectCalls(f);
                List<String> callNames = collectCallNames(f);
                List<String> extRefs = collectExternalRefs(f);
                if (err == null) {
                    try {
                        DecompileResults res = ifc.decompileFunction(f, timeoutSec, monitor);
                        if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                            body = res.getDecompiledFunction().getC();
                        } else {
                            err = res == null ? "null_result" : res.getErrorMessage();
                        }
                    } catch (Exception ex) {
                        err = ex.toString();
                    }
                }
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

    private int envInt(String key, int fallback) {
        try {
            String v = System.getenv(key);
            if (v == null || v.isEmpty()) return fallback;
            return Integer.parseInt(v);
        } catch (Exception e) {
            return fallback;
        }
    }

    private long envLong(String key, long fallback) {
        try {
            String v = System.getenv(key);
            if (v == null || v.isEmpty()) return fallback;
            return Long.parseLong(v);
        } catch (Exception e) {
            return fallback;
        }
    }

    private Set<String> loadExistingEas(File f) {
        Set<String> out = new LinkedHashSet<>();
        if (!f.exists()) return out;
        try {
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f));
            String line;
            while ((line = br.readLine()) != null) {
                String ea = extractEa(line);
                if (ea != null && !ea.isEmpty()) out.add(ea);
            }
            br.close();
        } catch (Exception e) {
            // ignore parse errors; full re-export will still work
        }
        return out;
    }

    private String extractEa(String line) {
        if (line == null) return null;
        int idx = line.indexOf("\"ea\":\"");
        if (idx < 0) return null;
        int start = idx + 6;
        int end = line.indexOf("\"", start);
        if (end <= start) return null;
        return line.substring(start, end);
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
