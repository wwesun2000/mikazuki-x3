// Called inside the current EE transaction. Buffers passed by the original
// card routines can live on the recompiled stack as well as in guest RAM.
bool PS2Runtime::card_call(u32 target,R5900Context& c){
    const u32 a0=c.word(4),a1=c.word(5),a2=c.word(6),a3=c.word(7);
    if(target==0x1fdc64){c.set32(2,u32(cstring(a0).size()));return true;}
    if(target==0x1fba18){
        const auto s=cstring(a0);const auto at=s.find(char(a1));
        c.set32(2,!std::uint8_t(a1)?a0+u32(s.size()):at==std::string::npos?0u:a0+u32(at));return true;
    }
    if(target==0x1fdb50 && (a0>=stack_base || a1>=stack_base || card_thread)){
        string_to(a0,cstring(a1));c.set32(2,a0);return true;
    }
    if(target==0x1fe108){
        if(a2>256)throw std::runtime_error("Oversized card path component");
        bool end=false;
        for(u32 i=0;i<a2;++i){auto ch=end?0u:u32(load(a1+i,1));store(a0+i,ch,1);end=!ch;}
        c.set32(2,a0);return true;
    }
    if(target==0x1fdf50){ // strncmp on the KMx3-RC01A header, including its NUL.
        for(u32 i=0;i<a2;++i){
            const auto l=load(a0+i,1),r=load(a1+i,1);
            if(l!=r || !l){c.set32(2,u32(l-r));return true;}
        }
        c.set32(2,0);return true;
    }
    if(target==0x1fd6e0){
        const auto fmt=cstring(a1);
        std::string out;unsigned arg=6;
        for(std::size_t i=0;i<fmt.size();++i){
            if(fmt[i]!='%'){out+=fmt[i];continue;}
            if(arg>=12)throw std::runtime_error("Unsupported original card formatter arguments");
            const auto value=c.word(arg++);
            if(fmt.compare(i,4,"%02d")==0 || fmt.compare(i,4,"%06d")==0){
                const auto digits=std::to_string(std::bit_cast<i32>(value));
                const std::size_t width=fmt[i+2]-'0';
                const bool negative=digits.front()=='-';
                if(negative)out+='-';
                if(digits.size()<width)out.append(width-digits.size(),'0');
                out.append(digits,negative?1:0);i+=3;
            }else if(fmt.compare(i,3,"%6d")==0){
                const auto digits=std::to_string(std::bit_cast<i32>(value));
                if(digits.size()<6)out.append(6-digits.size(),' ');
                out+=digits;i+=2;
            }else if(fmt.compare(i,4,"%-8s")==0){
                const auto s=cstring(value);out+=s;
                if(s.size()<8)out.append(8-s.size(),' ');
                i+=3;
            }else if(fmt.compare(i,2,"%d")==0){out+=std::to_string(std::bit_cast<i32>(value));++i;}
            else if(fmt.compare(i,2,"%s")==0){out+=cstring(value);++i;}
            else throw std::runtime_error("Unrecovered original card formatter conversion");
        }
        if(out.size()>=128)throw std::runtime_error("Invalid original card path length");
        string_to(a0,out);c.set32(2,u32(out.size()));return true;
    }
    if(target!=0x1661c0 && target!=0x1665d8 && target!=0x1663c0 &&
       target!=0x166840 && target!=0x161ad0 && target!=0x161a38 && target!=0x161ba0 &&
       target!=0x165fd0 && target!=0x165990 && target!=0x166038)return false;
    if(!services || !services->card)throw std::runtime_error("Chapter call requires a mounted card device");
    auto& card=*services->card;
    if(target==0x165fd0 || target==0x165990 || target==0x166038){
        const auto port=u32(load(a0+4,4));
        if(port){c.set32(2,0);return true;}
        const auto dir=cstring(a0+0x1c);
        const auto path=cstring(a0+0x6c);
        if(load(a0,4)!=5 || !path.starts_with(dir+"/"))throw std::runtime_error("Invalid original card path descriptor");
        if(target==0x165990){
            c.set32(2,card.stage_file(path,m.bytes(a2,a3),a1!=0));return true;
        }
        if(target==0x165fd0){ // Directory materializes with its first file in the transaction.
            c.set32(2,1);return true;
        }
        // 165D28 builds icon.sys from the per-title ELF descriptor, copies
        // the icon selected by 166DF8 from boot0:ICO, pads, then writes the
        // original 63-byte directory marker.
        const auto prefix=m.read_u32(0x235b24);
        if(prefix<1 || prefix>3)throw std::runtime_error("Unbound source card icon prefix");
        run_scenario_return(m,0x166c80,0x1e43558+(prefix-1)*0x3c4,0x22d6e0+(prefix-1)*0x1c0,services);
        run_scenario_return(m,0x166df8,0x1e43190,a0,services);
        const auto icon_name=cstring(0x1e43294);
        const auto& icon=card.icon(icon_name);
        bool ok=card.stage_file(dir+"/"+icon_name,icon,true);
        const auto pad=icon.size()<0x11400?((0x11400-icon.size())/1024)*1024:0;
        if(ok && pad)ok=card.stage_file(dir+"/icon.ali",m.bytes(0x22d348,pad),true);
        if(ok)ok=card.stage_file(dir+"/icon.sys",m.bytes(0x1e43190,0x3c4),true);
        if(ok)ok=card.stage_file(dir+"/BISLPM-66452"+dir,m.bytes(0x22d348,63),true);
        c.set32(2,ok);return true;
    }
    if(target==0x1661c0){
        // 1661C0 polls libmc GetInfo. A formatted PS2 card yields 0 and
        // free KiB, an empty port yields 2. No card-change event is injected.
        const std::array<u32,7> info{m.read_u32(0x207e80),a1,0,0,a1?2u:0u,
                                     a1?UINT32_MAX:card.free_clusters(),0};
        for(unsigned i=0;i<info.size();++i)store(a0+i*4,info[i],4);
        c.set32(2,1);return true;
    }
    if(target==0x161a38 || target==0x161ad0 || target==0x161ba0){
        // 161AD0 takes a destination descriptor (address, maximum length)
        // and returns the underlying read count used by 107008.
        const auto path=cstring(a2);
        const auto* file=path.starts_with("mc0:")?card.read(path.substr(4)):nullptr;
        if(target==0x161a38){
            // stat descriptor consumed by 1026C0: type, offsets and file length.
            if(file){
                // 160590 copies type and length only for the MC driver (5).
                store(a1,5,4);store(a1+12,file->size(),4);store(a1+20,0,4);
            }else{
                const std::array<u32,6> missing{0,UINT32_MAX,0,UINT32_MAX,UINT32_MAX,2};
                for(unsigned i=0;i<missing.size();++i)store(a1+4*i,missing[i],4);
            }
            c.set32(2,file!=nullptr);return true;
        }
        if(!file){store(a0+0x28,2,4);c.set32(2,UINT32_MAX);return true;}
        const auto dest=u32(load(a1,4));
        const auto n=std::min<std::size_t>(load(a1+4,4),file->size());
        for(std::size_t i=0;i<n;++i)store(dest+u32(i),(*file)[i],1);
        store(a0+0x28,0,4);c.set32(2,u32(n));return true;
    }
    if(target==0x166840){
        u32 total=0;
        u32 count=0;
        if(!a0)for(const auto& row:card.enumerate(cstring(a1))){
            if(row.name.starts_with("B"))continue;
            total+=(row.size+1023)&~1023u;
            if(++count==16)break;
        }
        if(count)total+=((count+1)/2+2)*1024;
        c.set32(2,total);return true;
    }
    const bool single=target==0x1663c0;
    const auto port=single?a1:a3;
    const auto pattern=cstring(single?a2:c.word(8));
    auto rows=port?std::vector<CardFileEntry>{}:card.enumerate(pattern);
    if(!single && pattern.find('/')!=std::string::npos)
        std::erase_if(rows,[](const auto& row){return row.name.starts_with("B");});
    if(single && !rows.empty() && rows[0].directory){
        const auto* marker=card.read(pattern+"/BISLPM-66452"+pattern);
        if(!marker)rows.clear();
        else rows[0].size=u32(marker->size());
    }
    const std::size_t n=std::min<std::size_t>(rows.size(),single?1:a2);
    for(unsigned i=0;i<n;++i){
        const auto p=a0+i*64;
        const auto& row=rows[i];
        if(row.name.size()>=16)throw std::runtime_error("Card directory name exceeds game record");
        u32 kind=row.directory?1:2;
        if(single && row.directory){
            const auto& marker=*card.read(pattern+"/BISLPM-66452"+pattern);
            const auto expected=m.bytes(0x22d348,63);
            kind=std::ranges::equal(marker,expected)?2:4;
        }
        store(p,kind,4);store(p+4,m.read_u32(0x207e80),4);
        store(p+8,port,4);store(p+12,row.size,4);string_to(p+16,row.name);
        using namespace std::chrono;
        const auto instant=sys_seconds(seconds(row.modified));
        const auto day=floor<days>(instant);
        const year_month_day date(day);
        const hh_mm_ss time(instant-day);
        const std::array<u32,7> stamp{0,u32(time.seconds().count()),u32(time.minutes().count()),u32(time.hours().count()),
                                      unsigned(date.day()),unsigned(date.month()),u32(int(date.year()))};
        for(unsigned j=0;j<stamp.size();++j)store(p+32+j*4,stamp[j],4);
    }
    if(single && !n){
        // 163EF8 resets the absent entry, using the actual original leaf.
        FUN_00163ef8_0x163ef8(nullptr,&c,this);
        c.set32(2,0);
    }else c.set32(2,port && !single?UINT32_MAX:u32(n));
    return true;
}
