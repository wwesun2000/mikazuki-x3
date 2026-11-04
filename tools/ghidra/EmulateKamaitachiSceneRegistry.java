// Execute 101420 with the file slot and heap represented by explicitly supplied source buffers.
// @category Kamaitachi
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;

@SuppressWarnings("removal")
public class EmulateKamaitachiSceneRegistry extends GhidraScript {
    private static final String ELF = "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final long REGISTRY = 0x400000, FILE = 0x500000, TABLE = 0x700000, RETURN = 0x310000;
    private Address at(long value) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value); }
    private static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static byte[] word(long value) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int)value).array();
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Path.of(args[0]), sourceDir = Path.of(args[2]);
        byte[] elf = Files.readAllBytes(Path.of(args[1]));
        if (!sha(elf).equals(ELF) || !ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"))
            throw new IllegalArgumentException("Wrong original executable or architecture");
        Files.createDirectory(output);
        List<Object> rows = new ArrayList<>();
        for (String name : List.of("sn2","sn4","sn4g")) {
            byte[] file = Files.readAllBytes(sourceDir.resolve(name + ".spk"));
            String fileHash = sha(file);
            EmulatorHelper emu = new EmulatorHelper(currentProgram);
            try {
                emu.writeMemory(at(FILE), file.clone());
                emu.writeMemory(at(REGISTRY), new byte[144]);
                emu.writeRegister("sp", 0x1ff0000);
                emu.writeRegister("gp", 0x23daf0);
                emu.writeRegister("ra", RETURN);
                emu.writeRegister(emu.getPCRegister(), 0x101420);
                for (long stop : new long[]{0x17a560,0x1007d8,RETURN}) emu.setBreakpoint(at(stop));
                int allocations = 0, fileSlots = 0, tableBytes = 0;
                while (true) {
                    monitor.checkCancelled();
                    if (!emu.run(monitor)) throw new IllegalStateException("Original execution failed: " + emu.getLastError());
                    long pc = emu.getExecutionAddress().getOffset(), a0 = emu.readRegister("a0").longValue();
                    if (pc == RETURN) break;
                    if (pc == 0x17a560) {
                        if (++allocations > 2 || (allocations == 1 && a0 != 144) ||
                            (allocations == 2 && (a0 <= 0 || a0 > 0x10000 || (a0 & 3) != 0)))
                            throw new IllegalStateException("Unexpected source allocation: " + a0);
                        if (allocations == 2) tableBytes = (int)a0;
                        emu.writeRegister("v0", allocations == 1 ? REGISTRY : TABLE);
                    } else if (pc == 0x1007d8 && a0 == 2 && ++fileSlots == 1) {
                        emu.writeMemory(at(emu.readRegister("a1").longValue()), word(FILE));
                        emu.writeRegister("v0", 0);
                    } else throw new IllegalStateException("Unexpected source boundary " + Long.toHexString(pc));
                    emu.writeRegister(emu.getPCRegister(), emu.readRegister("ra"));
                }
                if (allocations != 2 || fileSlots != 1 || emu.readRegister("v0").longValue() != REGISTRY)
                    throw new IllegalStateException("Incomplete registry construction");
                byte[] object = emu.readMemory(at(REGISTRY),144);
                rows.add(Map.of("program",name,"source_sha256",fileHash,"resident_bytes",file.length,
                    "resident_sha256",sha(emu.readMemory(at(FILE),file.length)),"registry_sha256",sha(object),
                    "cue_table_bytes",tableBytes,"cue_table_sha256",sha(emu.readMemory(at(TABLE),tableBytes))));
                println("Original scene registry returned: " + name);
            } finally { emu.dispose(); }
        }
        Map<String,Object> m = new LinkedHashMap<>();
        m.put("status","oracle_completed"); m.put("source_elf_sha256",ELF); m.put("source_entry","0x00101420");
        m.put("registry",REGISTRY); m.put("file_base",FILE); m.put("cue_table",TABLE);
        m.put("host_boundaries",List.of("17A560 heap returns caller-reserved address for two actual allocations",
            "1007D8 returns the selected original .spk at ready slot 2"));
        m.put("harness_sha256",sha(Files.readAllBytes(getSourceFile().getFile(false).toPath())));
        m.put("programs",rows);
        Files.writeString(output.resolve("manifest.json"),new GsonBuilder().setPrettyPrinting().create().toJson(m)+"\n",StandardOpenOption.CREATE_NEW);
    }
}
