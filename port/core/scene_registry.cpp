#include "scene_registry.hpp"
#include <optional>
#include <string_view>
#include <utility>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using Bytes = std::span<std::uint8_t>;

void require(bool ok, const char* message) {
    if (!ok) throw std::invalid_argument(message);
}
void range(u32 at, u32 bytes, u32 end) {
    require(at <= end && bytes <= end - at, "SPK record outside its source region");
}
u32 read(Bytes file, u32 at, unsigned width) {
    range(at, width, static_cast<u32>(file.size()));
    u32 value = 0;
    for (unsigned i = 0; i < width; ++i) value |= u32(file[at + i]) << (8 * i);
    return value;
}
void store(Bytes file, u32 at, u32 value, unsigned width) {
    range(at, width, static_cast<u32>(file.size()));
    for (unsigned i = 0; i < width; ++i) file[at + i] = std::uint8_t(value >> (8 * i));
}
void name_ends_at(Bytes file, u32 first, u32 end) {
    require(first < end && file[end - 1] == 0 &&
        std::find(file.begin() + first, file.begin() + end - 1, 0) == file.begin() + end - 1,
        "SPK name disagrees with variable record size");
}
bool signature(Bytes file, std::string_view expected) {
    return file.size() >= expected.size() && std::equal(expected.begin(), expected.end(), file.begin());
}
bool disjoint(u32 a, u32 length_a, u32 b, u32 length_b) {
    return a + length_a <= b || b + length_b <= a;
}

// 101710. Source helpers 101A70/AA8 and 101AC8/AF8 assemble and write
// unaligned LE words. Group/cue loops advance over the NUL and trailing fields.
void relocate_block(Bytes block, u32 base, std::vector<u32>& cue_index) {
    require(block.size() >= 0x430 && signature(block,{"ScenePack\0\0\0\0\0\0\0:Ver:3.25.2.157",32}),
            "Unknown SPK block");
    const auto size = static_cast<u32>(block.size());
    const auto groups = read(block, 0x420, 4), deps = read(block, 0x424, 4), programs = read(block, 0x428, 4);
    require(0x430 <= groups && groups <= deps && deps <= programs && programs <= size,
            "SPK section order or bounds invalid");
    store(block, 0x420, base + groups, 4);
    store(block, 0x424, base + deps, 4);
    store(block, 0x428, base + programs, 4);
    for (unsigned bucket = 0; bucket < 256; ++bucket) {
        const auto cell = 0x20 + 4 * bucket;
        auto scene = read(block, cell, 4);
        if (!scene) continue;
        require(scene >= 0x430, "SPK bucket overlaps header");
        range(scene, 2, groups);
        store(block, cell, base + scene, 4);
        const auto scene_count = read(block, scene, 2);
        require(scene_count <= 0x7fff, "Unsupported signed SPK scene count");
        scene += 2;
        for (unsigned s = 0; s < scene_count; ++s) {
            range(scene, 10, groups);
            const auto body_size = read(block, scene, 2);
            require(body_size >= 9, "Short SPK scene record");
            range(scene + 2, body_size, groups);
            const auto next = scene + 2 + body_size;
            name_ends_at(block, scene + 10, next);
            const auto group_offset = read(block, scene + 2, 4), dep_offset = read(block, scene + 6, 4);
            range(group_offset, 2, deps - groups);
            range(dep_offset, 2, programs - deps);
            auto cue = groups + group_offset;
            store(block, scene + 2, base + cue, 4);
            store(block, scene + 6, base + deps + dep_offset, 4);
            scene = next;
            const auto cue_count = read(block, cue, 2);
            require(cue_count <= 0x7fff, "Unsupported signed SPK cue count");
            cue += 2;
            for (unsigned c = 0; c < cue_count; ++c) {
                range(cue, 4, deps);
                const auto payload = read(block, cue + 2, 2);
                require(payload >= 7, "Short SPK cue");
                range(cue + 4, payload, deps);
                const auto end = cue + 4 + payload;
                name_ends_at(block, cue + 4, end - 6);
                const auto code = read(block, end - 6, 4);
                range(code, 1, size - programs);
                store(block, end - 6, base + programs + code, 4);
                require(cue_index.size() <= 0x7fff, "Cue index exceeds source signed16 reverse lookup");
                store(block, end - 2, static_cast<u32>(cue_index.size()), 2);
                // 101510 takes the address of this same cue header, indexed
                // by the signed trailer written by the first traversal.
                cue_index.push_back(base + cue);
                cue = end;
            }
        }
    }
}
}

SceneRegistryResult install_scene_registry(GuestMemory& memory, u32 registry, u32 file_base,
    std::span<const std::uint8_t> spk, u32 cue_table, u32 cue_capacity_bytes) {
    require(spk.size() >= 0xa4 && spk.size() <= GuestMemory::size, "Invalid SPK file size");
    const auto size = static_cast<u32>(spk.size());
    require(registry && file_base && cue_table && !((registry | file_base | cue_table) & 3),
            "Invalid SPK guest allocation");
    range(registry, 144, GuestMemory::size);
    range(file_base, size, GuestMemory::size);
    range(cue_table, cue_capacity_bytes, GuestMemory::size);
    require(disjoint(registry,144,file_base,size) && disjoint(registry,144,cue_table,cue_capacity_bytes) &&
            disjoint(file_base,size,cue_table,cue_capacity_bytes), "Overlapping SPK allocations");

    std::vector<std::uint8_t> resident(spk.begin(), spk.end());
    require(signature(resident,{"ScenarioLink\0\0\0\0:Ver:3.25.2.157",32}), "Unknown .spk file");
    const auto count = read(resident, 0xa0, 4);
    require(count > 0 && count <= 32, "Invalid SPK block count");
    std::array<std::uint8_t,144> object{};
    store(object,0,file_base,4);
    store(object,0x84,count,4);
    std::vector<u32> cues;
    u32 expected_offset = 0xa4 + count * 8;
    for (unsigned i = 0; i < count; ++i) {
        const auto at = 0xa4 + 8 * i;
        const auto offset = read(resident,at,4), length = read(resident,at+4,4);
        require(offset == expected_offset, "Noncontiguous SPK block");
        range(offset,length,size);
        // 1016C0 builds these 32 pointer slots before 101710 visits them.
        store(object,4+4*i,file_base+offset,4);
        relocate_block(Bytes(resident).subspan(offset,length), file_base+offset, cues);
        expected_offset += length;
    }
    require(expected_offset == size && cues.size() <= cue_capacity_bytes / 4, "SPK or reverse table size mismatch");
    const auto cue_count = static_cast<u32>(cues.size());
    store(object,0x88,cue_count,4);
    store(object,0x8c,cue_table,4);
    std::optional<GuestMemory::Transaction> transaction;
    if (!memory.transaction_active()) transaction.emplace(memory);
    memory.write_bytes(file_base,resident);
    memory.write_bytes(registry,object);
    for (unsigned i=0; i<cue_count; ++i) memory.write_u32(cue_table+4*i,cues[i]);
    if (transaction) transaction->commit();
    return {registry,file_base,cue_table,count,cue_count};
}

u32 construct_scene_provider(GuestMemory& m,u32 cold_storage){
    constexpr u32 slot=0x235efc; // gp - 0x7bf4 at 11DAC4
    if(const u32 live=m.read_u32(slot))return live;
    require(cold_storage && !(cold_storage&3),"Invalid scene provider allocation");
    range(cold_storage,32,GuestMemory::size);
    require(disjoint(cold_storage,32,slot,4),"Scene provider overlaps its pointer");
    m.write_u32(cold_storage,0x223770); // SW in the JR delay slot at 11DB5C.
    m.write_u32(slot,cold_storage);     // 11DAEC publishes the constructed object.
    return cold_storage;
}

SceneRegistryResult activate_scene_provider(GuestMemory& m,u32 cold_storage,u32 registry,u32 file_base,
        std::span<const std::uint8_t> spk,u32 cue_table,u32 cue_capacity_bytes){
    constexpr u32 slot=0x235efc; // gp - 0x7bf4 at 11DAC4
    const u32 live=m.read_u32(slot);
    const u32 self=live?live:cold_storage;
    require(self && !(self&3) && spk.size()<=GuestMemory::size,"Invalid scene provider allocation");
    range(self,32,GuestMemory::size);
    range(registry,144,GuestMemory::size);
    range(file_base,u32(spk.size()),GuestMemory::size);
    range(cue_table,cue_capacity_bytes,GuestMemory::size);
    for(const auto [address,size]:std::array<std::pair<u32,u32>,3>{{
            {registry,144},{file_base,u32(spk.size())},{cue_table,cue_capacity_bytes}}}){
        require(disjoint(self,32,address,size) && disjoint(slot,4,address,size),
                "Scene registry overlaps the original provider");
    }
    require(disjoint(self,32,slot,4),"Scene provider overlaps its pointer");
    std::optional<GuestMemory::Transaction> tx;
    if(!m.transaction_active())tx.emplace(m);
    construct_scene_provider(m,cold_storage);
    for(u32 off=8;off<32;off+=4)m.write_u32(self+off,0); // Last store in JAL 101420 delay slot at 11DB88.
    const auto loaded=install_scene_registry(m,registry,file_base,spk,cue_table,cue_capacity_bytes);
    m.write_u32(self+4,loaded.registry);
    if(tx)tx->commit();
    return loaded;
}
}
