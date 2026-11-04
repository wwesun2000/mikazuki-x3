#include "manager_bootstrap.hpp"
#include "scene_registry.hpp"
#include "font_constructor.hpp"
#include "recovered.hpp"
#include "manager_handler_bindings.hpp"
#include <bit>
#include <stdexcept>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;

class ObjectArena {
public:
    ObjectArena(u32 begin, u32 end) : cursor_(begin), end_(end) {}
    u32 allocate(u32 size) {
        const auto next = (u64(cursor_) + 63) & ~u64(63);
        const auto end = (next + size + 63) & ~u64(63);
        if (!size || end > end_) throw std::runtime_error("Cold manager object arena exhausted");
        cursor_ = static_cast<u32>(end);
        return static_cast<u32>(next);
    }
    u32 cursor() const { return cursor_; }
    void consume_to(u32 next) {
        if (next < cursor_ || next > end_) throw std::out_of_range("Cold constructor escaped its arena");
        cursor_ = next;
    }
private:
    u32 cursor_, end_;
};

template<std::size_t Count>
u32 install_factory(GuestMemory& memory, ObjectArena& arena, u32 manager, u32 offset,
                    u32 jump_table, const std::array<cold_factory::Binding, Count>& rows) {
    u32 constructed = 0;
    for (u32 slot = 0; slot < Count; ++slot) {
        const auto& row = rows[slot];
        if (slot < 135 && memory.read_u32(jump_table + 4 * slot) != row.branch)
            throw std::runtime_error("Cold manager factory differs from the original ELF");
        u32 object = 0;
        if (row.bytes) {
            object = arena.allocate(row.bytes);
            // All included original constructors are LUI/ADDIU/JR RA/SW vt.
            // Each opcode has its own allocation even when two vtables match.
            memory.write_u32(object, row.vtable);
            ++constructed;
        }
        memory.write_u32(manager + offset + 4 * slot, object);
    }
    return constructed;
}

void register_record(GuestMemory& memory, u32 registry, u32 object, u32 bytes) {
    const auto index = memory.read_u32(registry + 0xf4);
    if (index >= 20) throw std::runtime_error("Cold manager registry capacity exceeded");
    memory.write_u32(registry + index * 12 + 4, object);
    memory.write_u32(registry + index * 12 + 8, (bytes + 63) & ~63u);
    memory.write_u32(registry + 0xf4, index + 1);
}

void initialize_simple_modes(GuestMemory& m, ObjectArena& arena, u32 manager, u32 registry) {
    // All listed stores are from 110660 or its named object constructors.
    // Extra heap bytes retain the caller's chosen initial contents.
    auto object = [&](u32 offset, u32 size) {
        const auto ptr = arena.allocate(size);
        m.write_u32(manager + offset, ptr);
        return ptr;
    };
    const auto choice = object(8, 0x1d4); // 117C80 -> 117D00(choice,1)
    m.write_u32(choice, 0x223650);
    m.write_u32(choice + 12, 1);
    for (u32 offset : {0x18cu,0x190u,0x194u}) m.write_u32(choice + offset, 0);
    object(0x0c, 0x78); // 1108C4 -> 118E40, JR RA / NOP.
    m.write_u32(object(0x10, 0x118), 0); // 1108DC -> 119258, JR RA / SW ZERO,0(A0).
    m.write_u32(object(0x14, 8), 0); // 119560
    m.write_u32(object(0x18, 0xcc) + 0xc8, 0);
    m.write_u32(object(0x1c, 0x54) + 0x50, 0);
    const auto special = object(0x20, 0x34); // 119DA0
    m.write_u32(special, 0x223660);
    for (u32 offset : {4u,0x2cu,0x30u}) m.write_u32(special + offset, 0);
    register_record(m, registry, special, 4);
    const auto mode = object(0x24, 0x14); // 11A0D0
    for (u32 i = 0; i < 5; ++i) m.write_u32(mode + i * 4, 0);
    const auto resume = object(0x28, 0x18); // 11A200
    m.write_u32(resume + 0x10, 0); m.write_u32(resume + 0x14, 0);
    const auto alternate = object(0x2c, 0x14); // 11A3A8
    for (u32 offset : {0u,4u,8u}) m.write_u32(alternate + offset, 0);
    m.write_u32(object(0x30, 0x14), 0); // 11A518
}

void initialize_fields(GuestMemory& m, u32 manager, u32 registry) {
    // 111550(manager,1), 1135F8, 1134D0, 1126C0 and explicit 110660 stores.
    for (u32 offset : {0x294u,0x2acu,0x44u,0x2b4u,0x2b8u,0x2c0u,0x2d0u,0x2d4u,
                       0x2d8u,0x2dcu,0x2e8u,0x2ecu,0x32cu,0x73cu,0x740u,0x744u,
                       0x748u,0x74cu,0x76cu,0x808u,0x834u,0x838u})
        m.write_u32(manager + offset, 0);
    for (u32 offset : {0x298u,0x29cu,0x2a4u,0x2bcu}) m.write_u32(manager + offset, 1);
    // 113AE0 preference constructor and 10BB68 registration.
    for (u32 offset = 4; offset <= 0x20; offset += 4) m.write_u32(manager + 0x308 + offset, 0);
    register_record(m, registry, manager + 0x308, 32);
    // 113CD0: ten 100-byte records; only active and completion words are reset.
    for (u32 i = 0; i < 10; ++i) {
        m.write_u32(manager + 0x330 + i * 100, 0);
        m.write_u32(manager + 0x330 + i * 100 + 12, 0);
    }
    m.write_u32(manager + 0x718, 1); m.write_u32(manager + 0x71c, 0); m.write_u32(manager + 0x720, 0);
    // 114B30 chooses 50/70/100 and publishes it through 1358F8.
    const auto mode = m.read_u32(0x235b00);
    const u32 value = mode == 0 ? 50 : mode == 2 ? 70 : 100;
    m.write_u32(manager + 0x730, value); m.write_u32(manager + 0x734, value); m.write_u32(manager + 0x738, 0);
    m.write_u32(0x206260, value);
    m.write_u32(0x2070fc,0x10c8d0); // 100910 -> 135C98, fade completion handler
    register_record(m, registry, manager + 0x724, 4);
    register_record(m, registry, manager + 0x804, 16); // 115BE0
}

void construct_format_stack(GuestMemory& m,u32 manager,u32 object,u32 backing){
    // 110808 -> 116370(12,1): a single 12-byte snapshot of +294/+298/+29C.
    m.write_u32(object,1);m.write_u32(object+4,0);
    m.write_u32(object+8,12);m.write_u32(object+12,backing);m.write_u32(manager+0x2a0,object);
}

void initialize_input_objects(GuestMemory& m, u32 manager, ObjectArena& arena, u32 registry) {
    // Independent post-ScriptData children in 110660. First four invoke base
    // 121730 (clear +4) and replace its vtable with their concrete vtable.
    auto create = [&](u32 field, u32 bytes, u32 vtable) {
        const auto ptr = arena.allocate(bytes);
        m.write_u32(ptr, vtable); m.write_u32(ptr + 4, 0);
        m.write_u32(manager + field, ptr);
        return ptr;
    };
    const auto first = create(0x844, 0x20, 0x223be0);
    m.write_u32(first + 20, 0); m.write_u32(first + 24, 1);
    (void)create(0x84c, 0x14, 0x223c10);
    (void)create(0x854, 0x14, 0x223c40);
    const auto last = create(0x850, 0x30, 0x223c70);
    m.write_u32(last + 28, 3); m.write_u32(last + 20, 0x223ca4);
    register_record(m, registry, last + 20, 4);
    const auto owner = create(0x848, 0xc, 0x223cb8);
    m.write_u32(owner + 8, 0);
}

void initialize_tasks(GuestMemory& m, ObjectArena& arena) {
    // 179EB8 -> 179F00, 179FB8. Inactive records retain their other heap bytes.
    const auto tasks = arena.allocate(37 * 48);
    m.write_u32(0x2388bc, tasks);
    for (u32 i = 0; i < 37; ++i) {
        m.write_u32(tasks + 48 * i, 0);
        m.write_u32(tasks + 48 * i + 4, 0);
    }
    m.write_u32(0x2388c0, m.read_u32(0x237278));
}

void install_context(GuestMemory& m,const cold_factory::Context& row,u32 address) {
    m.write_u32(address,row.primary);
    if(row.secondary)m.write_u32(address+4,row.secondary);
    m.write_u32(row.cell,address);
}

void initialize_choice_overlay(GuestMemory& m,ObjectArena& arena,u32 manager) {
    // Last child of 110660. 17D2A8(0,0,0) takes the first available slot
    // in the 179B58 class-1 range [10,12] and allocates a 32-byte payload.
    const auto table=m.read_u32(0x2388bc);
    u32 slot=10;
    while(slot<=12 && m.read_u32(table+48*slot))++slot;
    if(slot>12)throw std::runtime_error("17D2A8 choice task pool exhausted");
    const u32 task=table+48*slot, data=arena.allocate(32);
    for(u32 off=0;off<48;off+=4)m.write_u32(task+off,0);
    m.write_u32(task,1);m.write_u32(task+8,1);m.write_u32(task+20,0x17d3e0);
    m.write_u32(task+24,0x17d450);m.write_u32(task+32,0x17d4d0);m.write_u32(task+44,data);
    for(u32 off:{0u,4u,8u,28u})m.write_u32(data+off,0);
    const auto level=m.read_u8(0x237360);
    m.write_u32(data+12,level);
    const auto bits=std::bit_cast<u32>(float(level));
    for(u32 off:{16u,20u,24u})m.write_u32(data+off,bits);
    m.write_u32(manager+0x58,task);
}

void initialize_readback(GuestMemory& m, ObjectArena& arena, u32 manager) {
    // 1109D4 and 116548, including the registered task created by 185B78.
    const auto object = arena.allocate(64);
    m.write_u32(object + 4, 0);
    m.write_u32(object, 1);
    const auto tasks = m.read_u32(0x2388bc);
    u32 task = tasks + 1584; // 179B58 mode 4 -> ELF jump target 179C24
    while (task <= tasks + 1728 && m.read_u32(task)) task += 48;
    if (task > tasks + 1728) throw std::runtime_error("Original readback task pool exhausted at 0x00179B58");
    for (u32 offset = 0; offset < 48; offset += 4) m.write_u32(task + offset, 0);
    m.write_u32(task, 1);
    m.write_u32(task + 8, 4);
    m.write_u32(task + 12, 1);
    m.write_u32(task + 32, 0x186008);
    const auto payload = arena.allocate(4); // 17A560(4, ..., 176, 0, 13)
    m.write_u32(task + 44, payload);
    m.write_u32(payload, m.read_u32(0x2386f0)); // 10B278(0), current source resource handle
    m.write_u32(object + 48, task);
    m.write_u32(object + 52, m.read_u32(manager + 0x38));
    m.write_u32(object + 20, 0);
    m.write_u32(object + 60, 0);
    m.write_u32(manager + 4, object);
}
}

ColdDispatchRuntime bootstrap_manager_dispatch(GuestMemory& destination, std::optional<ReadyScenarioResource>& slot,
        u32 begin, u32 end, u32 script_begin, u32 script_end, ChoiceServices& services,
        std::span<const std::uint8_t> font_file, u32 descriptor,const ReadySceneResource* slot2) {
    if (!slot || destination.transaction_active() || begin < 0x240000 || begin >= end || end > GuestMemory::size ||
        script_begin < 0x240000 || script_begin >= script_end || script_end > GuestMemory::size ||
        (begin < script_end && script_begin < end) || font_file.empty() ||
        (descriptor < script_end && u64(descriptor) + font_file.size() > script_begin) ||
        (descriptor < end && u64(descriptor) + font_file.size() > begin))
        throw std::runtime_error("Invalid cold manager resources or arena ranges");
    if (destination.read_u32(0x235e40) || destination.read_u32(0x235cd8) ||
        destination.read_u32(0x235f3c) || destination.read_u32(0x235f40))
        throw std::runtime_error("Cold manager requires vacant original singleton globals");
    GuestMemory m;
    m.write_bytes(0, destination.bytes(0, GuestMemory::size));
    ObjectArena arena(begin, end);
    ColdDispatchRuntime result;
    const auto manager = result.manager = arena.allocate(0x858); // 10FB38 -> 110628
    m.write_u32(0x235e40, manager);
    m.write_u32(manager, 0x223610); m.write_u32(manager + 0x804, 0x223620);
    m.write_u32(manager + 0x308, 0x223640); m.write_u32(manager + 0x724, 0x223630);
    if(slot2)construct_scene_provider(m,slot2->provider_storage); // 11068C, before the context constructors.
    // 110694..110760 calls each singleton getter in this order. The source
    // skips allocation if already published. Six derived contexts also set
    // the final secondary vtable through the base offset stored at vt-12.
    for(const auto& row : cold_factory::contexts) {
        if(m.read_u32(row.cell))continue;
        install_context(m,row,arena.allocate(row.secondary?8:4));
    }
    result.default_context=m.read_u32(0x235f3c);
    m.write_u32(manager + 0x40, result.default_context);
    result.constructed_handlers = install_factory(m, arena, manager, 0x5c, 0x229784, cold_factory::opcode);
    result.null_handlers = static_cast<u32>(cold_factory::opcode.size()) - result.constructed_handlers;
    (void)install_factory(m, arena, manager, 0x280, 0x229770, cold_factory::auxiliary);
    result.registry = arena.allocate(0xfc); // 10BA78 -> 10BB10
    m.write_u32(result.registry, 0x2235e8); m.write_u32(result.registry + 0xf4, 0);
    m.write_u32(result.registry + 0xf8, 0); m.write_u32(0x235cd8, result.registry);
    // 110778..1107B4: four 153488 creations and four 153A70 releases.
    // The serialized native session owns its semaphore domain. Source clients
    // observe distinct live handles, the released owner (-1) and zero wait state.
    const std::array<u32,4> locks{0x205588,0x205598,0x2055a8,manager+0x48};
    u32 handle = 1;
    for (const auto lock : locks) {
        m.write_u32(lock, handle++);
        m.write_u32(lock + 4, 0xffffffffu);
        m.write_u32(lock + 8, 0);
        m.write_u32(lock + 12, 0);
    }
    const auto font = construct_font_object(m, arena.cursor(), end, descriptor, font_file);
    arena.consume_to(font.arena_used_end);
    m.write_u32(manager + 0x3c, font.font); // 1107E4
    initialize_tasks(m, arena);
    // 110660 calls 100D40 before creating manager settings and ScriptData.
    // The original variable store is a static 512-word (s16) table.
    for (u32 i = 0; i < 512; ++i) m.write_u16(0x238af0 + i * 2, 0);
    m.write_u32(0x238684, 0);
    const auto format_stack=arena.allocate(16);
    construct_format_stack(m,manager,format_stack,arena.allocate(12));
    initialize_fields(m, manager, result.registry);
    (void)invoke_recovered(m, 0x1114f8, manager); // 110834 initial page clear
    if(slot2){ // 110840 reacquires the singleton. 110848 calls 11DB60 with that pointer.
        activate_scene_provider(m,slot2->provider_storage,slot2->registry,slot2->file_base,
                                slot2->file,slot2->cue_table,slot2->cue_capacity);
    }
    initialize_simple_modes(m, arena, manager, result.registry);
    auto ready = slot;
    result.script = bootstrap_script_data(m, ready, script_begin, script_end, services);
    initialize_readback(m, arena, manager);
    initialize_input_objects(m, manager, arena, result.registry);
    initialize_choice_overlay(m,arena,manager);
    result.manager_arena_used_end = arena.cursor();
    destination.replace_contents(std::move(m));
    slot.reset();
    return result;
}

void restore_missing_panel_modes(GuestMemory& m,u32 manager) {
    if(!manager || m.read_u32(0x235e40)!=manager)throw std::runtime_error("Invalid saved panel manager");
    // Dedicated space between the audio worker and card worker, independent
    // of the old heap end. Existing children and live menu addresses stay put.
    constexpr u32 first=0x1351200,memo=0x1351280;
    GuestMemory::Transaction tx(m);
    if(!m.read_u32(manager+0x0c))m.write_u32(manager+0x0c,first);
    if(!m.read_u32(manager+0x10)){
        const bool published=m.read_u32(0x2387d0)==0xd4 && m.read_u32(0x2387d4)==12;
        // 119270 sets the active word and creates 1..12 option slots before
        // 1192C8 publishes the three interior pointers and clears the word.
        const bool prepared=m.read_u32(0)==1 && m.read_u32(4)>0 && m.read_u32(4)<=12;
        if(published || prepared)m.write_bytes(memo,m.bytes(0,0x118));
        else m.write_u32(memo,0);
        if(published){
            m.write_u32(0x2387d0,memo+0xd4);m.write_u32(0x2387d4,memo+12);
            if(m.read_u32(0x236730)==8)m.write_u32(0x236730,memo+8);
            const auto queued=m.read_u32(0x235fa8);
            if(queued>16)throw std::runtime_error("Invalid saved panel request count");
            for(u32 i=0;i<queued;++i){
                const auto args=0x23a720+16*i,target=m.read_u32(args);
                if(m.read_u32(0x23a6e0+4*i)==0x14a048 && (target==8 || target==12))
                    m.write_u32(args,memo+target);
            }
        }
        m.write_u32(manager+0x10,memo);
    }
    tx.commit();
}

void restore_missing_choice_bootstrap(GuestMemory& m,u32 manager,u32 begin,u32 end) {
    constexpr auto contexts=cold_factory::contexts.size();
    if(begin<0x240000 || begin%64 || end>GuestMemory::size || u64(begin)+(contexts+1)*64>end ||
       !manager || m.read_u32(0x235e40)!=manager || m.transaction_active())
        throw std::runtime_error("Invalid choice migration memory or caller");
    GuestMemory::Transaction tx(m);
    for(u32 i=0;i<contexts;++i) {
        const auto& row=cold_factory::contexts[i];
        const u32 previous=m.read_u32(row.cell),slot=begin+64*i;
        if(previous) {
            if((previous>=begin && previous<end && previous!=slot) || m.read_u32(previous)!=row.primary ||
               (row.secondary && m.read_u32(previous+4)!=row.secondary))
                throw std::runtime_error("Saved context does not match its source virtual table");
        } else install_context(m,row,slot);
    }
    const auto table=m.read_u32(0x2388bc),current=m.read_u32(manager+0x58);
    if(!table || table>GuestMemory::size-37*48)throw std::runtime_error("Invalid saved task pool");
    if(current) {
        if(current<table+10*48 || current>table+12*48 || (current-table)%48 || !m.read_u32(current) ||
           m.read_u32(current+8)!=1 || m.read_u32(current+24)!=0x17d450 || !m.read_u32(current+44))
            throw std::runtime_error("Saved choice task does not match 17D2A8");
        (void)m.bytes(m.read_u32(current+44),32);
    } else {
        ObjectArena reserve(begin+64*u32(contexts),std::min(end,begin+0x780u));
        initialize_choice_overlay(m,reserve,manager);
    }
    if(!m.read_u32(manager+0x2a0)){
        static_assert((contexts+1)*64<=0x780);
        if(end-begin<0x800)throw std::runtime_error("Missing original format stack in legacy save");
        construct_format_stack(m,manager,begin+0x780,begin+0x7c0);
    }else{
        const auto stack=m.read_u32(manager+0x2a0);
        if((stack>=begin && stack<end && stack!=begin+0x780) || m.read_u32(stack)!=1 ||
           m.read_u32(stack+4)>1 || m.read_u32(stack+8)!=12 || !m.read_u32(stack+12) ||
           (stack==begin+0x780 && m.read_u32(stack+12)!=begin+0x7c0))
            throw std::runtime_error("Saved format stack does not match 116370");
        (void)m.bytes(m.read_u32(stack+12),12);
    }
    tx.commit();
}
}
