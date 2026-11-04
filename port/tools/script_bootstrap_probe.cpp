#include "../core/script_bootstrap.hpp"
#include "../core/choice_pipeline.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {
using u32 = std::uint32_t;
using Bytes = std::vector<std::uint8_t>;
constexpr u32 manager = 0x300000, special = 0x301000, registry = 0x302000;
constexpr u32 begin = 0x400000, end = 0x1000000;
void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
Bytes read_file(const char* path, std::size_t limit) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input || input.tellg() < 0 || static_cast<std::size_t>(input.tellg()) > limit)
        throw std::runtime_error("Invalid bounded input file");
    const auto size = static_cast<std::size_t>(input.tellg());
    input.seekg(0);
    Bytes bytes(size);
    if (size && !input.read(reinterpret_cast<char*>(bytes.data()), size)) throw std::runtime_error("Input read failed");
    return bytes;
}
u32 word(const Bytes& data, std::size_t i) {
    require(i <= data.size() && data.size() - i >= 4, "ELF word out of range");
    return u32(data[i]) | (u32(data[i+1]) << 8) | (u32(data[i+2]) << 16) | (u32(data[i+3]) << 24);
}
void install_original_file_data(kx3::GuestMemory& memory, const Bytes& elf) {
    require(elf.size() == 1290132 && word(elf, 0) == 0x464c457fu && elf[4] == 1 && elf[5] == 1,
            "Unexpected original executable");
    const u32 program_header = word(elf, 28);
    require(word(elf, program_header) == 1 && word(elf, program_header + 4) == 0x1000 &&
            word(elf, program_header + 8) == 0x100000, "Original PT_LOAD mismatch");
    const u32 size = word(elf, program_header + 16);
    require(size == 0x138648 && size <= elf.size() - 0x1000, "Invalid original file segment");
    memory.write_bytes(0x100000, std::span(elf).subspan(0x1000, size));
}
class NoColdCallbacks final : public kx3::ChoiceServices {
public:
    bool supports_source(u32) const override { return false; }
    std::uint64_t call_source(kx3::GuestMemory&,u32,std::span<const std::uint64_t>) override {
        throw std::runtime_error("Unexpected callback during initial label transfer");
    }
    bool supports_effect(kx3::ChoiceEffectKind) const override { return false; }
    bool glyph_animation_pending() const override { throw std::runtime_error("Unexpected glyph query during cold construction"); }
};
void install_test_dependencies(kx3::GuestMemory& memory, bool with_registry) {
    // Explicit startup prerequisites only. The original 119DA0 clears +4,
    // +2C,+30, writes 223660 and registers that object with byte size 4.
    memory.write_u32(0x235e40, manager);
    memory.write_u32(manager, 0x223610);
    memory.write_u32(manager + 0x20, special);
    memory.write_u32(special, 0x223660);
    memory.write_u32(special + 4, 0);
    memory.write_u32(special + 0x2c, 0);
    memory.write_u32(special + 0x30, 0);
    if (with_registry) {
        memory.write_u32(0x235cd8, registry);
        memory.write_u32(registry, 0x2235e8);
        memory.write_u32(registry + 4, special);
        memory.write_u32(registry + 8, 64);
        memory.write_u32(registry + 12, 0xdeadbeef);
        memory.write_u32(registry + 0xf4, 1);
    }
}
std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (auto v : bytes) { result += digits[v >> 4]; result += digits[v & 15]; }
    return result;
}
void check_state(kx3::GuestMemory& m, const kx3::ScriptBootstrapResult& r, std::uint8_t fill) {
    const auto self = r.index.self;
    require(m.read_u32(self) == 0x2235f8 && m.read_u32(manager + 0x38) == self, "Publication/vtable mismatch");
    require(m.read_u32(0x238ac0) == 0 && m.read_u32(0x238ac4) == 0xffffffff, "Consumed slot state mismatch");
    require(m.read_u32(self + 0xdc) == r.entry_cursor && m.read_u32(self + 0xd8) == r.entry_cursor, "Cursor mismatch");
    require(hex(m.bytes(self + 0xe4, 3)) == "93a700" && hex(m.bytes(self + 0xf4, 5)) == "905e979d00", "Original names mismatch");
    require(m.read_u8(self + 0xe7) == fill && m.read_u8(self + 0x174) == fill, "Untouched object bytes changed");
    for (u32 i = r.index.block_count; i < 32; ++i) require(!m.read_u32(self + 8 + i * 4), "Unused block slot is not zero");
    const u32 old_word = 0x01010101u * fill;
    for (u32 i = 0; i < r.index.label_count; ++i) {
        require(m.read_u32(r.history + 8 * i) == 0x0fffffffu &&
                m.read_u32(r.history + 8 * i + 4) == ((old_word & 0xfe000000u) | 0x00ffffffu),
                "History initialization mismatch");
        const auto symbol = m.read_u32(r.index.labels + 4 * i);
        require(m.read_u16(symbol + 2) == i, "Label index points to wrong ID");
    }
    for (const auto backup : r.backups) {
        require(!(backup & 127), "Backup alignment mismatch");
        const auto bytes = m.bytes(backup, r.index.label_count * 8);
        require(std::all_of(bytes.begin(), bytes.end(), [=](auto b) { return b == fill; }), "Backup history was initialized");
    }
    for (u32 i = 0; i < 15; ++i) {
        const auto block = m.read_u32(self + 8 + 4 * (32 + i));
        require(!(block & 127) && !m.read_u32(block + 0x2c) && m.read_u32(block + 0x430) == block + 0x434,
                "Runtime block header mismatch");
        require(m.read_u8(block + 0x30) == fill, "Untouched template header changed");
        if (i < 10) {
            auto code = hex(m.bytes(block + 0x434, 22));
            require(code.substr(0, 20) == "500000000043092b0282" && m.read_u8(block + 0x43e) == 0x60 + i &&
                    code.substr(22) == "814603500000000043001b", "Option template mismatch");
        } else {
            const auto name = self + 0xe4 + (i - 10) * 16;
            std::array<std::uint8_t, 15> expected{};
            expected.fill(0x21); expected[0] = 2; expected[13] = 3; expected[14] = 0x1b;
            for (u32 j = 0; m.read_u8(name + j); ++j) expected.at(j + 1) = m.read_u8(name + j);
            require(std::equal(expected.begin(), expected.end(), m.bytes(block + 0x434, 15).begin()), "Name template mismatch");
        }
    }
    require(m.read_u32(r.registry + 0xf4) == r.registration_index + 1 &&
            m.read_u32(r.registry + 4 + r.registration_index * 12) == self &&
            m.read_u32(r.registry + 8 + r.registration_index * 12) == ((r.index.label_count * 8 + 0x9f) & ~63u),
            "Registration mismatch");
    if (r.registration_index) require(m.read_u32(r.registry + 12) == 0xdeadbeef, "Earlier registry word changed");
}
}
int main(int argc, char** argv) {
    try {
        require(argc == 4 || argc == 5, "Usage: script_bootstrap_probe original.elf source.sn4 heap_fill [check-failure]");
        auto fill_value = std::stoul(argv[3], nullptr, 0);
        require(fill_value <= 255, "Invalid heap fill");
        const auto fill = static_cast<std::uint8_t>(fill_value);
        const auto elf = read_file(argv[1], 2 * 1024 * 1024);
        const auto bytes = read_file(argv[2], 8 * 1024 * 1024);
        kx3::GuestMemory m;
        install_original_file_data(m, elf);
        m.write_bytes(begin, Bytes(end - begin, fill));
        install_test_dependencies(m, fill != 0);
        const bool test_failure = argc == 5;
        Bytes before;
        if (test_failure) before.assign(m.bytes(0, m.size).begin(), m.bytes(0, m.size).end());
        NoColdCallbacks services;
        std::optional<kx3::ReadyScenarioResource> slot{{bytes, static_cast<u32>(bytes.size())}};
        auto result = kx3::bootstrap_script_data(m, slot, begin, end, services);
        require(!slot, "Host resource was not consumed");
        check_state(m, result, fill);
        if (test_failure) {
            kx3::GuestMemory retry;
            retry.write_bytes(0, before);
            std::optional<kx3::ReadyScenarioResource> retained{{bytes, static_cast<u32>(bytes.size())}};
            const auto insufficient = result.backups.back() + ((result.index.label_count * 8 + 127) & ~127u) - 1;
            bool rejected = false;
            try { (void)kx3::bootstrap_script_data(retry, retained, begin, insufficient, services); }
            catch (const std::runtime_error& e) { rejected = std::string(e.what()).find("arena exhausted") != std::string::npos; }
            require(rejected && retained && retained->bytes == bytes &&
                    std::equal(before.begin(), before.end(), retry.bytes(0, retry.size).begin()), "Failed build changed RAM or consumed resource");
            const auto recovered = kx3::bootstrap_script_data(retry, retained, begin, end, services);
            require(!retained && recovered.entry_cursor == result.entry_cursor &&
                    std::equal(m.bytes(0, m.size).begin(), m.bytes(0,m.size).end(), retry.bytes(0,retry.size).begin()),
                    "Retry differs from first successful construction");
        }
        std::cout << "{\"status\":\"passed\",\"blocks\":" << result.index.block_count << ",\"labels\":" << result.index.label_count
                  << ",\"self\":" << result.index.self << ",\"image\":" << result.index.image
                  << ",\"selector\":" << result.selector << ",\"label_id\":" << result.label_id
                  << ",\"entry_cursor\":" << result.entry_cursor << ",\"entry_relative\":" << result.code_relative_offset
                  << ",\"entry_bytes_hex\":\"" << hex(m.bytes(result.entry_cursor,16)) << "\",\"reserved_end\":" << result.arena_used_end
                  << ",\"registry_index\":" << result.registration_index << ",\"registration_bytes\":" << result.registration_size
                  << ",\"heap_fill\":" << fill_value << ",\"failure_rollback_retry\":" << (test_failure ? "true" : "false") << "}\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 2; }
}
