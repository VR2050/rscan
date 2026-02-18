// ghidra_export_pseudocode.java
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
