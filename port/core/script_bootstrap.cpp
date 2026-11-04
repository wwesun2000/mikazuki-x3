#include "script_bootstrap.hpp"
#include "choice_pipeline.hpp"
#include "script_data.hpp"
#include "source_libc.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;
constexpr u32 manager_global = 0x235e40;
constexpr u32 registry_global = 0x235cd8;
constexpr u32 resource_slot3 = 0x238aa8 + 3 * 8;
constexpr u32 registry_vtable = 0x2235e8;
constexpr u32 script_vtable = 0x2235f8;
constexpr u32 special_vtable = 0x223660;
constexpr u32 minimum_heap = 0x240000;

u32 aligned(u64 value, u32 alignment) {
    const auto result = (value + alignment - 1) & ~u64(alignment - 1);
    if (result > GuestMemory::size) throw std::runtime_error("Script allocation exceeds guest RAM");
    return static_cast<u32>(result);
}
bool overlaps(u32 start, u32 length, u32 begin, u32 end) {
    return u64(start) < end && u64(start) + length > begin;
}
void validate_service_object(u32 address, u32 length, u32 begin, u32 end) {
    if (address < minimum_heap || (address & 3) || u64(address) + length > GuestMemory::size ||
        overlaps(address, length, begin, end))
        throw std::runtime_error("Invalid or overlapping ScriptData service object");
}
class Arena {
public:
    Arena(u32 cursor, u32 end) : cursor_(cursor), end_(end) {}
    u32 allocate(u32 size, u32 alignment) {
        const auto address = aligned(cursor_, alignment);
        // Model the data allocator's rounded payload extent without filling it.
        const auto next = aligned(u64(address) + size, alignment);
        if (next > end_) throw std::runtime_error("Reserved ScriptData arena exhausted");
        cursor_ = next;
        return address;
    }
    u32 cursor() const { return cursor_; }
private:
    u32 cursor_, end_;
};

void initialize_object(GuestMemory& memory, u32 self) {
    // Original 10CAF0 writes selected words and one byte per name slot.
    memory.write_u32(self, script_vtable);
    for (u32 i = 0; i < 47; ++i) memory.write_u32(self + 8 + i * 4, 0);
    for (u32 offset : {0xd0u, 0xd8u, 0xdcu, 0x14cu, 0x150u, 0x15cu, 0x16cu, 0x184u})
        memory.write_u32(self + offset, 0);
    for (u32 offset : {0xd4u, 0xe0u}) memory.write_u32(self + offset, 0xffffffffu);
    for (u32 offset : {0x168u, 0x180u}) memory.write_u32(self + offset, 1);
    for (u32 i = 0; i < 5; ++i) memory.write_u8(self + 0xe4 + i * 16, 0);
    (void)source_strcpy(memory, self + 0xe4, 0x235e30);
    (void)source_strcpy(memory, self + 0xf4, 0x235e38);
}

void initialize_templates(GuestMemory& memory, u32 self, Arena& arena) {
    // 10D038 writes only block+2C, +430 and this 22-byte instruction stream.
    std::array<std::uint8_t, 22> code{0x50,0,0,0,0,0x43,9,0x2b,2,0x82,0x60,
                                      0x81,0x46,3,0x50,0,0,0,0,0x43,0,0x1b};
    for (u32 i = 0; i < 10; ++i) {
        const auto block = arena.allocate(0x44a, 128);
        memory.write_u32(self + 8 + (32 + i) * 4, block);
        memory.write_u32(block + 0x2c, 0);
        memory.write_u32(block + 0x430, block + 0x434);
        code[10] = static_cast<std::uint8_t>(0x60 + i);
        memory.write_bytes(block + 0x434, code);
    }
    for (u32 i = 0; i < 5; ++i) {
        const auto block = arena.allocate(0x443, 128);
        memory.write_u32(self + 8 + (42 + i) * 4, block);
        memory.write_u32(block + 0x2c, 0);
        memory.write_u32(block + 0x430, block + 0x434);
        (void)invoke_script_data(memory, 0x10d4c8, self, i, self + 0xe4 + i * 16);
    }
}

void initialize_history(GuestMemory& memory, ScriptBootstrapResult& result, Arena& arena) {
    const auto self = result.index.self;
    const auto count = memory.read_u32(self + 0xc8);
    const auto bytes = count * 8; // load_script_index has validated the 16-bit ID space.
    memory.write_u32(self + 0x134, count);
    result.history = arena.allocate(bytes, 128);
    memory.write_u32(self + 0x138, result.history);
    for (u32 i = 0; i < result.backups.size(); ++i) {
        result.backups[i] = arena.allocate(bytes, 128);
        memory.write_u32(self + 0x13c + i * 4, result.backups[i]);
    }
    memory.write_u32(self + 0x148, 0);
    for (u32 i = 0; i < count; ++i) {
        const auto record = result.history + i * 8;
        memory.write_u32(record, 0x0fffffffu);
        const auto old = memory.read_u32(record + 4);
        memory.write_u32(record + 4, (old & 0xfe000000u) | 0x00ffffffu);
    }
}

void register_script(GuestMemory& memory, ScriptBootstrapResult& result, Arena& arena) {
    auto registry = memory.read_u32(registry_global);
    if (registry == 0) {
        registry = arena.allocate(0xfc, 64);
        memory.write_u32(registry, registry_vtable);
        memory.write_u32(registry + 0xf4, 0);
        memory.write_u32(registry + 0xf8, 0);
        memory.write_u32(registry_global, registry);
    }
    const auto count = memory.read_u32(registry + 0xf4);
    if (count >= 20) throw std::runtime_error("Original ScriptData registration table is full");
    result.registry = registry;
    result.registration_index = count;
    result.registration_size = aligned(u64(result.index.label_count) * 8 + 0x60, 64);
    memory.write_u32(registry + 4 + count * 12, result.index.self);
    memory.write_u32(registry + 8 + count * 12, result.registration_size);
    memory.write_u32(registry + 0xf4, count + 1);
}
}

ScriptBootstrapResult bootstrap_script_data(GuestMemory& original,
        std::optional<ReadyScenarioResource>& slot3, u32 begin, u32 end,
        ChoiceServices& choice_services) {
    if (!slot3 || slot3->bytes.empty() || slot3->bytes.size() > 8u * 1024 * 1024)
        throw std::runtime_error("Expected a ready bounded ScenarioLink resource in slot 3");
    if (begin < minimum_heap || begin >= end || end > GuestMemory::size || original.transaction_active())
        throw std::runtime_error("Invalid cold ScriptData reservation or execution state");
    const auto manager = original.read_u32(manager_global);
    validate_service_object(manager, 0x854, begin, end);
    const auto special = original.read_u32(manager + 0x20);
    validate_service_object(special, 0x34, begin, end);
    if (overlaps(special, 0x34, manager, manager + 0x854) ||
        original.read_u32(special) != special_vtable || original.read_u32(special + 4) != 0)
        throw std::runtime_error("ScriptData requires the original normal-mode manager context");
    const auto previous = original.read_u32(manager + 0x38);
    if (previous >= minimum_heap && previous <= GuestMemory::size - 0x188 &&
        original.read_u32(previous) == script_vtable)
        throw std::runtime_error("Manager already owns a constructed ScriptData object");
    const auto registry = original.read_u32(registry_global);
    if (registry) {
        validate_service_object(registry, 0xfc, begin, end);
        if (overlaps(registry, 0xfc, manager, manager + 0x854) || overlaps(registry, 0xfc, special, special + 0x34) ||
            original.read_u32(registry) != registry_vtable)
            throw std::runtime_error("Unexpected save-registration singleton");
    }
    constexpr std::array<std::uint8_t, 3> first_name{0x93, 0xa7, 0};
    constexpr std::array<std::uint8_t, 5> second_name{0x90, 0x5e, 0x97, 0x9d, 0};
    if (!std::equal(first_name.begin(), first_name.end(), original.bytes(0x235e30, 3).begin()) ||
        !std::equal(second_name.begin(), second_name.end(), original.bytes(0x235e38, 5).begin()) ||
        original.read_u32(script_vtable) != 0x10f4e0)
        throw std::runtime_error("Missing original ScriptData ELF constants");
    if (original.read_u32(resource_slot3) != 0)
        throw std::runtime_error("Guest slot 3 already owns a published resource");

    // Keep both host service and caller RAM unchanged until all phases succeed.
    // The shared index loader owns its own transaction. A private working RAM
    // image preserves untouched heap bytes and avoids nested guest transactions.
    GuestMemory staged;
    staged.write_bytes(0, original.bytes(0, GuestMemory::size));
    auto self = aligned(begin, 64);
    // The shared loader uses 64-byte placement. Choose its start so the real
    // 17A560 label table is also 128-byte aligned for each actual input size.
    if (aligned(u64(aligned(u64(self) + 0x188, 64)) + slot3->bytes.size(), 64) % 128)
        self = aligned(u64(self) + 64, 64);
    const auto image = aligned(u64(self) + 0x188, 64);
    if (u64(image) + slot3->bytes.size() > end) throw std::runtime_error("ScenarioLink asset exceeds script arena");
    initialize_object(staged, self);
    staged.write_bytes(image, slot3->bytes);
    staged.write_u32(resource_slot3, image);
    staged.write_u32(resource_slot3 + 4, slot3->completion_word);
    // 100718/1007D8 ready path. The consumed bytes remain owned by ScriptData.
    const auto acquired = staged.read_u32(resource_slot3);
    staged.write_u32(resource_slot3, 0);
    staged.write_u32(resource_slot3 + 4, 0xffffffffu);
    ScriptBootstrapResult result;
    result.index = load_script_index(staged, staged.bytes(acquired, slot3->bytes.size()), self, end);
    if (result.index.self != self || result.index.image != acquired || (result.index.labels & 127))
        throw std::logic_error("Shared script-index placement contract changed");
    Arena arena(result.index.end, end);
    {
        GuestMemory::AccessBudget budget(staged, 8'000'000);
        GuestMemory::Transaction transaction(staged);
        initialize_templates(staged, self, arena);
        const auto label = image + 0x20; // Original 175F78(5) returns zero.
        const auto header_field = staged.bytes(label, 64);
        if (!header_field.front() || std::find(header_field.begin(), header_field.end(), 0) == header_field.end())
            throw std::runtime_error("Missing or unterminated initial ScenarioLink label");
        result.selector = static_cast<u32>(invoke_script_data(staged, 0x10f9b0, self, label, 0));
        if (result.selector >= result.index.block_count) throw std::runtime_error("Initial ScenarioLink label was not found");
        // Constructor D4=-1 makes the recovered transfer skip previous-label
        // recording. The real normal-mode object and source label lookup are used.
        choice_transfer_transactional(staged, self, result.selector, label, 0, choice_services);
        (void)invoke_script_data(staged, 0x10d728, self, 0, 0);
        result.label_id = staged.read_u32(self + 0xd4);
        result.entry_cursor = staged.read_u32(self + 0xd8);
        const auto block = staged.read_u32(self + 8 + result.selector * 4);
        result.code_relative_offset = result.entry_cursor - staged.read_u32(block + 0x430);
        initialize_history(staged, result, arena);
        staged.write_u32(self + 0x170, 0);
        register_script(staged, result, arena);
        // Original 1109D0 publishes the constructed object's saved pointer.
        staged.write_u32(manager + 0x38, self);
        result.arena_used_end = arena.cursor();
        transaction.commit();
    }
    original.replace_contents(std::move(staged));
    slot3.reset();
    return result;
}
}
