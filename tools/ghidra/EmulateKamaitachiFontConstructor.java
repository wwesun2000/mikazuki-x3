// Execute the original font object constructor using native-port service boundaries.
// @category Kamaitachi.Evidence
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;

@SuppressWarnings("removal")
public class EmulateKamaitachiFontConstructor extends GhidraScript {
    private static final String ELF="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final int ARENA=0x600000, END=0x640000, FILE=0x900000, STACK=0x1ff0000, SENTINEL=0x3ff000;
    private Address at(long n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
    private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void check(boolean ok,String msg){if(!ok)throw new IllegalStateException(msg);}
    private static byte[] word(int n){return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(n).array();}

    private Map<String,Object> runCase(byte[] elf,byte[] file,String program,int fill)throws Exception {
        byte[] initial=new byte[32*1024*1024];
        System.arraycopy(elf,0x1000,initial,0x100000,0x138648);
        Arrays.fill(initial,ARENA,END,(byte)fill);
        Arrays.fill(initial,0x1e44200,0x1e444f0,(byte)fill);
        System.arraycopy(file,0,initial,FILE,file.length);
        EmulatorHelper emu=new EmulatorHelper(currentProgram);
        try {
            emu.writeMemory(at(0),initial);
            emu.writeRegister("gp",0x23daf0);emu.writeRegister("sp",STACK);
            emu.writeRegister("ra",SENTINEL);emu.writeRegister("a0",ARENA);
            emu.writeRegister(emu.getPCRegister(),0x16a098);
            int next=ARENA+64, steps=0,files=0,uploads=0; List<Integer> sizes=new ArrayList<>();
            while(!emu.getExecutionAddress().equals(at(SENTINEL))){
                monitor.checkCancelled(); int pc=(int)emu.getExecutionAddress().getOffset();
                check(++steps<120000,"Font constructor exceeded instruction budget");
                switch(pc){
                case 0x1007d8: // File slot 4 is ready, backed by the original font bytes.
                    check(emu.readRegister("a0").intValue()==4 && ++files==1,"Unexpected slot request");
                    emu.writeMemory(at(emu.readRegister("a1").longValue()),word(FILE));
                    emu.writeRegister(emu.getPCRegister(),emu.readRegister("ra"));
                    break;
                case 0x1686e0: // Guest addresses come from the caller's reserved heap.
                    int bytes=emu.readRegister("a0").intValue();
                    check(bytes>0 && bytes<END-next,"Unexpected font allocation");
                    sizes.add(bytes);emu.writeRegister("v0",next);
                    next=(next+bytes+63)&~63;
                    emu.writeRegister(emu.getPCRegister(),emu.readRegister("ra"));
                    break;
                case 0x16c390:
                    // The source CLUT arithmetic has finished. Exclude the PS2
                    // FlushCache/GIF/DMA packet and synchronization sequence.
                    check(++uploads==1,"Repeated CLUT upload");
                    emu.writeRegister(emu.getPCRegister(),0x16c424);break;
                case 0x15dbd8:
                    check(uploads==1 && emu.readRegister("a0").intValue()==4 &&
                          emu.readRegister("ra").intValue()==0x16c180,"Unexpected GS completion");
                    emu.writeRegister(emu.getPCRegister(),emu.readRegister("ra"));break;
                default:
                    check(pc>=0x168000 && pc<0x16d000,"Unexpected original dependency "+Integer.toHexString(pc));
                    check(emu.step(monitor),"R5900 step failed "+Integer.toHexString(pc)+" "+emu.getLastError());
                }
            }
            check(files==1 && uploads==1,"Source service coverage incomplete");
            byte[] result=emu.readMemory(at(0),initial.length);
            Arrays.fill(result,STACK-0x400,STACK,(byte)0);
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("program",program);row.put("fill",fill);row.put("source_file_sha256",sha(file));
            row.put("steps_including_boundaries",steps);row.put("inner_allocation_requests",sizes);
            row.put("arena_used_end",next);row.put("arena_sha256",sha(Arrays.copyOfRange(result,ARENA,END)));
            row.put("ram_without_abi_stack_sha256",sha(result));
            return row;
        } finally {emu.dispose();}
    }
    @Override public void run()throws Exception {
        String[] args=getScriptArgs();
        check(args.length==3,"Expected new output, source ELF, SCENARIO directory");
        byte[] elf=Files.readAllBytes(Path.of(args[1]));
        check(sha(elf).equals(ELF)&&ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256())&&
              "r5900:LE:32:default".equals(currentProgram.getLanguageID().toString()),"Unexpected source program");
        Path output=Path.of(args[0]);Files.createDirectory(output);
        Map<String,String> expected=Map.of("sn2","396d03ea918799696e06495813c0369c8059b18c1ddf1e74b4d1595b4bb84738",
            "sn4","a3dac7e146cc970e4c8ae2c191afa4ffd2592765c0f11e300a66b7ddf12d00c7",
            "sn4g","c12f602b3716b1dce68d6bdbcb58b45dbe29d67dab0a5ef7dbb35210e3d370b3");
        List<Object> cases=new ArrayList<>();
        for(String name: List.of("sn2","sn4","sn4g")){
            byte[] file=Files.readAllBytes(Path.of(args[2],name+".fnt"));
            check(sha(file).equals(expected.get(name)),"Unexpected original font");
            for(int fill:new int[]{0,0xa5})cases.add(runCase(elf,file,name,fill));
        }
        Map<String,Object> record=new LinkedHashMap<>();
        record.put("status","oracle_completed");record.put("source_elf_sha256",ELF);record.put("entry","0x0016a098");
        record.put("harness_sha256",sha(Files.readAllBytes(getSourceFile().getFile(false).toPath())));
        record.put("scope","R5900 Ghidra instruction execution with ready slot 4, reserved 64-aligned arena and host CLUT upload boundary");
        record.put("excluded","Original disk queue, heap bookkeeping, GS/DMA/cache synchronization, and 1 KiB of guest ABI call stack");
        record.put("arena_begin",ARENA);record.put("arena_end",END);record.put("font_descriptor",FILE);record.put("cases",cases);
        Files.writeString(output.resolve("manifest.json"),new GsonBuilder().setPrettyPrinting().create().toJson(record)+"\n",StandardOpenOption.CREATE_NEW);
    }
}
