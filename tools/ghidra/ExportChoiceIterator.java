// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
public class ExportChoiceIterator extends GhidraScript {
    @Override public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong game executable");
        int[][] tables={{0x225f40,0x169d68,0x169d98,0x169db8,0x169df0},
                        {0x225ec8,0x1682e8,0x1682f0,0x168338,0x1683b0,0x168330}};
        for(int[] row:tables)for(int n=1;n<row.length;n++){
            if(getInt(toAddr(row[0]+4*(n-1)))!=row[n])throw new IllegalStateException("Changed original glyph vtable");
            var at=toAddr(row[n]);
            if(getFunctionAt(at)==null && (getFunctionContaining(at)!=null ||
               (getInstructionAt(at)==null && !disassemble(at)) || createFunction(at,String.format("FUN_%08x",row[n]))==null))
                throw new IllegalStateException("Cannot resolve glyph virtual function "+at);
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
