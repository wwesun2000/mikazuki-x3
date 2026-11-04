// Decompile five slot7 font vtable targets inside a transaction that always rolls back.
// @category Kamaitachi.Evidence
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class InspectKamaitachiFontLeaves extends GhidraScript {
    private static final String ELF = "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final long[] TARGETS = {0x1682e8, 0x1682f0, 0x168338, 0x1683b0, 0x168330};
    private static final int[] LENGTHS = {8, 8, 8, 24, 8};
    private static final long[] TABLES = {0x225ef0, 0x225f18};
    private final Gson gson = new GsonBuilder().setPrettyPrinting().serializeNulls().create();
    private Address at(long value) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value); }
    private static void require(boolean ok, String message) { if (!ok) throw new IllegalStateException(message); }
    private static String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static int fileOffset(long address) { return Math.toIntExact(address - 0xff000); }
    private static long u32(byte[] bytes, int offset) {
        return Integer.toUnsignedLong(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(offset));
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        require(args.length == 3 || (args.length == 4 && Set.of("input-gate","wait-context").contains(args[3])),
                "Expected new-output directory, original ELF, slot7 plan and optional verified vtable profile");
        boolean gate = args.length == 4 && args[3].equals("input-gate");
        boolean waitContext = args.length == 4 && args[3].equals("wait-context");
        long[] targets = gate ? new long[]{0x122220} : waitContext ? new long[]{0x11fee8,0x1200f8} : TARGETS;
        int[] lengths = gate ? new int[]{0x8c} : waitContext ? new int[]{8,8} : LENGTHS;
        Path out = Path.of(args[0]);
        require(!Files.exists(out), "Refusing existing output");
        Files.createDirectories(out);
        byte[] original = Files.readAllBytes(Path.of(args[1]));
        JsonObject plan = JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
        byte[] ram = Files.readAllBytes(Path.of(plan.get("ram_input_path").getAsString()));
        require(hash(original).equals(ELF) && ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()), "Source identity mismatch");
        require(plan.get("ram_sha256").getAsString().equals(hash(ram)) && ram.length == 0x2000000, "RAM identity mismatch");
        require(currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"), "Wrong language");
        long manager = u32(ram, 0x235e40), font = u32(ram, (int)manager + 0x3c);
        if (gate) {
            long gateObject = u32(ram, (int)manager + 0x850);
            require(u32(ram, (int)gateObject) == 0x223c70 &&
                    u32(ram, 0x223c78) == targets[0] &&
                    u32(original, fileOffset(0x223c78)) == targets[0],
                    "Original manager gate object and vtable mismatch");
        } else if (waitContext) {
            for (int i = 0; i < 2; i++) {
                long table = 0x2239b0 + i * 0x20;
                long object = u32(ram, 0x235f34 + i * 4);
                require(u32(ram, (int)object) == table && u32(ram, (int)table + 4) == targets[i] &&
                        u32(original, fileOffset(table + 4)) == targets[i], "Wait singleton/vtable mismatch");
            }
        } else for (int entity = 0; entity < TABLES.length; entity++) {
            long formatter = u32(ram, (int)font + 4 * entity);
            require(u32(ram, (int)formatter) == TABLES[entity], "Snapshot font vtable mismatch");
            for (int slot = 0; slot < TARGETS.length; slot++) {
                long pointer = TABLES[entity] + 4 * slot;
                require(u32(original, fileOffset(pointer)) == TARGETS[slot] && u32(ram, (int)pointer) == TARGETS[slot],
                    "Original ELF/runtime table entry mismatch");
            }
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        int before = fm.getFunctionCount();
        Map<String,Object> manifest = new LinkedHashMap<>();
        manifest.put("source_sha256", ELF);
        manifest.put("ram_sha256", hash(ram));
        manifest.put("vtables", gate ? List.of("0x00223c70") : waitContext ? List.of("0x002239b0","0x002239d0") : List.of("0x00225ef0", "0x00225f18"));
        manifest.put("boundary_authority", "Original ELF vtable, live object and exact JR/return-delay closure; temporary evidence-guided functions");
        byte[] source;
        try (var input = getSourceFile().getInputStream()) { source = input.readAllBytes(); }
        Files.write(out.resolve("InspectKamaitachiFontLeaves.java"), source);
        manifest.put("harness_sha256", hash(source));
        manifest.put("before_functions", before);
        List<Map<String,Object>> results = new ArrayList<>();
        int transaction = currentProgram.startTransaction("Inspect verified font vtable leaves transiently");
        var decompiler = new DecompInterface();
        try {
            require(decompiler.openProgram(currentProgram), "Cannot open decompiler");
            for (int slot = 0; slot < targets.length; slot++) {
                long entry = targets[slot];
                int length = lengths[slot];
                int offset = fileOffset(entry);
                byte[] actual = new byte[length];
                require(currentProgram.getMemory().getBytes(at(entry), actual) == length &&
                        Arrays.equals(actual, Arrays.copyOfRange(original, offset, offset + length)) &&
                        Arrays.equals(actual, Arrays.copyOfRange(ram, (int)entry, (int)entry + length)),
                        "Function bytes differ from ELF or RAM");
                require(u32(actual, length - 8) == 0x03e00008, "Body does not close with JR RA plus its delay");
                for (int i = 0; i < length; i += 4)
                    require(fm.getFunctionContaining(at(entry + i)) == null, "Overlapping existing function");
                if (getInstructionAt(at(entry)) == null) require(disassemble(at(entry)), "Cannot decode verified leaf");
                List<Object> instructions = new ArrayList<>();
                for (int i = 0; i < length; i += 4) {
                    Instruction ins = getInstructionAt(at(entry + i));
                    require(ins != null && ins.getLength() == 4, "Incomplete original instruction range");
                    if (!ins.getFlowType().isCall())
                        for (Address flow : ins.getFlows())
                            require(flow.getOffset() >= entry && flow.getOffset() < entry + length,
                                    "Non-call branch escaped proposed boundary");
                    instructions.add(Map.of("address", ins.getAddress().toString(), "raw_hex", HexFormat.of().formatHex(ins.getBytes()),
                        "disassembly", ins.toString()));
                }
                AddressSet body = new AddressSet(at(entry), at(entry + length - 1));
                Function created = fm.createFunction(String.format("FONT_SLOT_%08x", entry), at(entry), body, SourceType.USER_DEFINED);
                require(created != null && created.getBody().equals(body), "Could not create exact transient boundary");
                decompiler.flushCache();
                var result = decompiler.decompileFunction(created, 30, monitor);
                require(result.decompileCompleted() && result.getDecompiledFunction() != null, "No complete pseudocode");
                Map<String,Object> record = new LinkedHashMap<>();
                record.put("entry", String.format("0x%08x", entry));
                record.put("slot", gate ? 2 : waitContext ? 1 : slot);
                record.put("bytes", length);
                record.put("raw_sha256", hash(actual));
                record.put("instructions", instructions);
                record.put("decompilation", result.getDecompiledFunction().getC());
                results.add(record);
            }
        } finally {
            decompiler.dispose();
            // GhidraScript owns an outer transaction. A nested abort may be
            // applied only when that outer transaction closes. Explicitly
            // release only the profile's verified transient functions first.
            for (long entry : targets) {
                Function temporary = fm.getFunctionAt(at(entry));
                if (temporary != null && temporary.getName().equals(String.format("FONT_SLOT_%08x", entry)))
                    require(fm.removeFunction(at(entry)), "Could not remove a verified temporary function");
            }
            currentProgram.endTransaction(transaction, false);
            require(fm.getFunctionCount() == before, "Function count changed after rollback");
            for (long entry : targets) require(fm.getFunctionAt(at(entry)) == null, "Temporary function survived rollback");
            manifest.put("after_functions", fm.getFunctionCount());
            manifest.put("temporary_functions_explicitly_removed", true);
            manifest.put("transaction_rollback_requested", true);
            manifest.put("project_scope", "Headless read-only process");
            manifest.put("functions", results);
            manifest.put("status", results.size() == targets.length ? (gate ? "gate_inspected" : waitContext ? "wait_context_inspected" : "font_leaves_inspected") : "incomplete");
            Files.writeString(out.resolve("manifest.json"), gson.toJson(manifest));
        }
    }
}
