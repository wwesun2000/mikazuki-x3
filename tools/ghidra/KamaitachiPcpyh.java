// Isolated R5900 PCPYH emulator semantics with a real-instruction lane test.
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

@SuppressWarnings("removal")
public final class KamaitachiPcpyh {
    private static final BigInteger MASK = BigInteger.valueOf(65535);
    private static final BigInteger REPEAT = new BigInteger("0001000100010001", 16);
    public long executions;

    public KamaitachiPcpyh(EmulatorHelper helper) {
        if (!helper.getLanguage().getLanguageID().toString().equals("r5900:LE:32:default"))
            throw new IllegalArgumentException("PCPYH requires the verified R5900 language");
        helper.registerCallOtherCallback("_pcpyh", new BreakCallBack() {
            @Override public boolean pcodeCallback(PcodeOpRaw op) {
                if (op.getNumInputs() != 2 || op.getOutput() == null ||
                    op.getOutput().getSize() != 16 || op.getInput(1).getSize() != 16)
                    throw new IllegalStateException("Unexpected PCPYH signature");
                var state = emulate.getMemoryState();
                BigInteger source = state.getBigInteger(op.getInput(1), false);
                BigInteger low = source.and(MASK).multiply(REPEAT);
                BigInteger high = source.shiftRight(64).and(MASK).multiply(REPEAT);
                if (!(op.getOutput().isRegister() && op.getOutput().getOffset() == 0))
                    state.setValue(op.getOutput(), high.shiftLeft(64).or(low));
                executions++;
                return true;
            }
        });
    }

    public static Map<String,Object> validate(Program program, TaskMonitor monitor) throws Exception {
        final int cases = 256;
        var instruction = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1fc704);
        byte[] original = new byte[4];
        program.getMemory().getBytes(instruction, original);
        if (!HexFormat.of().formatHex(original).equals("e91e0870"))
            throw new IllegalStateException("PCPYH validation instruction differs from the original ELF");
        var random = new Random(0x52485043L);
        var digest = MessageDigest.getInstance("SHA-256");
        var emulator = new EmulatorHelper(program);
        try {
            var handler = new KamaitachiPcpyh(emulator);
            for (int i = 0; i < cases; i++) {
                byte[] bigEndian = new byte[16];
                random.nextBytes(bigEndian);
                if (i == 0) Arrays.fill(bigEndian, (byte) 0);
                if (i == 1) Arrays.fill(bigEndian, (byte) 255);
                // Independent reference: copy each 64-bit half's lowest
                // two bytes into its four 16-bit lanes, in register order.
                byte[] expected = new byte[16];
                for (int lane = 0; lane < 8; lane++)
                    System.arraycopy(bigEndian, lane < 4 ? 6 : 14, expected, lane * 2, 2);
                emulator.writeRegister("t0_qw", new BigInteger(1, bigEndian));
                emulator.writeRegister(emulator.getPCRegister(), instruction.getOffset());
                if (!emulator.step(monitor) || !emulator.readRegister("v1_qw").equals(new BigInteger(1, expected)))
                    throw new IllegalStateException("Original PCPYH lane mismatch at case " + i);
                digest.update(bigEndian);
                digest.update(expected);
            }
            if (handler.executions != cases) throw new IllegalStateException("PCPYH callback count mismatch");
        } finally { emulator.dispose(); }
        return Map.of("original_pc", "0x001fc704", "original_hex", "e91e0870", "passed", cases,
                      "input_reference_output_sha256", HexFormat.of().formatHex(digest.digest()),
                      "reference", "PCSX2 MMI.cpp PCPYH commit d983b2b0665c40acb0455433eb656eebcb9efaf2");
    }
}
