// ISO-backed file and allocation services used by the original 14D6E8 loader.
bool staff_device_call(PS2Runtime& runtime,u32 target,u32 pc,R5900Context& c){
    auto& m=runtime.m;
    if(target==0x16be70 && (pc>=0x14dba8 && pc<0x14df38 || pc>=0x16bfa8 && pc<0x16c164)){
        c.set64(2,invoke_recovered(m,target,c.word(4),c.r[5].lo,c.r[6].lo,0,runtime.services));
        return true;
    }
    if(pc<0x14d630 || pc>=0x14d868)return false;
    switch(target){
    case 0x145980:case 0x1453a8:case 0x1458c0:case 0x1456f8:{
        constexpr const char* paths[]{"edit0:STFROLL/sn4_stf.txt","edit0:STFROLL/sn4g_stf.txt","edit0:STFROLL/sn2_stf.txt"};
        const auto id=m.read_u32(credits::edition),size=m.read_u32(credits::file_size);
        if(id>=3 || !size || runtime.cstring(c.word(4))!=paths[id])throw std::runtime_error("Unbound staff roll ISO request");
        if(target==0x1453a8){
            if(c.word(5)!=0x8000 || c.word(6))throw std::runtime_error("Unknown staff file request flags");
            m.write_u32(credits::file_ready,2);c.set32(2,0);
        }else if(target==0x145980)c.set32(2,m.read_u32(credits::file_ready));
        else c.set32(2,target==0x1458c0?size:credits::source);
        return true;
    }
    case 0x151ee0:
        if(c.word(5)!=9)throw std::runtime_error("Unexpected staff allocator class");
        if(c.word(6)==0x22c528 && c.word(4)==m.read_u32(credits::file_size))c.set32(2,credits::copy);
        else if(c.word(6)==0x22c540 && c.word(4)==0x2df00)c.set32(2,credits::surfaces);
        else throw std::runtime_error("Unknown original staff allocation");
        return true;
    case 0x151f10:
        if(c.word(4)!=credits::copy && c.word(4)!=credits::surfaces)throw std::runtime_error("Unowned staff allocation");
        c.set32(2,0);return true;
    default:return false;
    }
}
