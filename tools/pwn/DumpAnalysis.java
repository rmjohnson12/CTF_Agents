// DumpAnalysis.java — Ghidra headless postScript
//
// Usage (invoked automatically by HeadlessGhidraTool):
//   analyzeHeadless <project_dir> <project_name> -import <binary> \
//       -postScript DumpAnalysis.java <strings.tsv> <imports.tsv> <exports.tsv> <functions.tsv>
//
// Produces four tab-separated artifact files in the paths given as script args.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.FileWriter;
import java.io.PrintWriter;

public class DumpAnalysis extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String stringsPath   = args.length > 0 ? args[0] : "strings.tsv";
        String importsPath   = args.length > 1 ? args[1] : "imports.tsv";
        String exportsPath   = args.length > 2 ? args[2] : "exports.tsv";
        String functionsPath = args.length > 3 ? args[3] : "functions.tsv";

        dumpStrings(stringsPath);
        dumpImports(importsPath);
        dumpExports(exportsPath);
        dumpFunctions(functionsPath);
    }

    private void dumpStrings(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            Listing listing = currentProgram.getListing();
            DataIterator it = listing.getDefinedData(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Data d = it.next();
                DataType dt = d.getDataType();
                if (dt != null && dt.getName() != null
                        && dt.getName().toLowerCase().contains("string")) {
                    String s = d.getValue() != null ? d.getValue().toString() : "";
                    if (s.length() > 0) {
                        pw.println(d.getAddress().toString() + "\t" + s);
                    }
                }
            }
        }
    }

    private void dumpImports(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator it = st.getExternalSymbols();
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                pw.println(s.getName(true));
            }
        }
    }

    private void dumpExports(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator it = st.getSymbolIterator(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Symbol s = it.next();
                if (!s.isExternal() && s.getAddress() != null && s.isGlobal()) {
                    pw.println(s.getAddress().toString() + "\t" + s.getName(true));
                }
            }
        }
    }

    private void dumpFunctions(String outPath) throws Exception {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {
            FunctionManager fm = currentProgram.getFunctionManager();
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                pw.println(f.getEntryPoint().toString() + "\t" + f.getName());
            }
        }
    }
}
