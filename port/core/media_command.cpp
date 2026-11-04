#include "media_command.hpp"
#include "guest_memory.hpp"
#include "manager_ops.hpp"
#include "script_data.hpp"
#include "source_libc.hpp"

#include <utility>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;
constexpr u32 loader = 0x206250;
constexpr u64 sx(u32 value) noexcept {
    return (value & 0x80000000u) ? 0xffffffff00000000ull | value : value;
}
constexpr bool positive32(u32 value) noexcept { return value != 0 && (value >> 31) == 0; }
constexpr bool signed_less(u64 a, u64 positive) noexcept { return (a >> 63) != 0 || a < positive; }

// 101A70 / 101AA8 are byte assemblers, accepting unaligned guest addresses.
u64 little_word(GuestMemory& m, u32 at) {
    auto value = static_cast<u32>(m.read_u8(at));
    const auto b1 = static_cast<u32>(m.read_u8(at + 1));
    const auto b2 = static_cast<u32>(m.read_u8(at + 2));
    value |= b1 << 8;
    const auto b3 = static_cast<u32>(m.read_u8(at + 3));
    value |= b2 << 16;
    return sx(value | (b3 << 24));
}
u64 little_half(GuestMemory& m, u32 at) {
    const auto high = static_cast<u32>(m.read_u8(at + 1)); // Source reads high first.
    const auto value = static_cast<u32>(m.read_u8(at)) | (high << 8);
    return sx((value & 0x8000u) ? value | 0xffff0000u : value);
}
u32 resource_hash(GuestMemory& m, u32 text) {
    u32 total = 0;
    auto byte = m.read_u8(text);
    while (byte != 0) {
        ++text;
        const auto part = static_cast<u32>(byte) << (byte & 7u);
        byte = m.read_u8(text);
        total += part;
    }
    return ((total & 255u) + (total >> 8)) & 255u;
}
struct Lookup { u32 group = 0; u32 descriptor = 0; bool found = false; };

// 101B58: each scene bucket begins with a signed16 count; each record starts
// with a u16 relative span, followed by two unaligned LE32 words and the name.
Lookup lookup(GuestMemory& m, u32 registry, u32 token) {
    const auto hash = resource_hash(m, token);
    auto count = m.read_u32(registry + 0x84);
    u32 block_index = 0;
    if (!positive32(count)) return {};
    do {
        const auto block = m.read_u32(registry + 4 + (block_index << 2));
        auto record = m.read_u32(block + 0x20 + (hash << 2));
        if (record != 0) {
            const auto length = static_cast<u32>(little_half(m, record));
            record += 2;
            if (positive32(length)) {
                for (u32 i = 0; i < length; ++i) {
                    const auto span = static_cast<u32>(little_half(m, record)) & 0xffffu;
                    const auto body = record + 2;
                    const auto next = body + span;
                    if (source_strcmp(m, sx(body + 8), token) == 0) {
                        const auto group = static_cast<u32>(little_word(m, body));
                        const auto descriptor = static_cast<u32>(little_word(m, body + 4));
                        return {group, descriptor, true};
                    }
                    record = next;
                }
            }
            count = m.read_u32(registry + 0x84); // Source reload after a non-null bucket.
        }
        ++block_index;
    } while (positive32(count) && block_index < count);
    return {};
}

u64 busy(GuestMemory& m) { // 137318.
    const auto state = m.read_u32(loader);
    if (state == 8) return 0;
    if (m.read_u32(loader + 0x5bc) != 0) return 1;
    return sx(state - 1u) < 7 ? 2 : 0;
}
u64 ready(GuestMemory& m) { // 137350: consumer first, then producer.
    if (busy(m) != 0) return 0;
    const auto consumer = m.read_u32(loader + 0xea4);
    const auto producer = m.read_u32(loader + 0xea0);
    return producer == consumer ? 1 : 0;
}
u64 permitted(GuestMemory& m, u32 gp) {
    if (gp == 0) throw std::invalid_argument("media_command requires explicit guest gp");
    return m.read_u32(gp - 0x7a2c) == 0 ? 1 : 0; // 1373B8, separate from readiness.
}
u32 provider(GuestMemory& m, u32 gp) {
    if (gp == 0) throw std::invalid_argument("media_command requires explicit guest gp");
    const auto value = m.read_u32(gp - 0x7bf4);
    if (value == 0) throw std::runtime_error("11dac0 cold provider unresolved: 10fad0 allocator and 11db50 constructor");
    return value;
}

// 137578/137598 tail1375D8. Queued and inhibitor paths are closed source logic;
// active media preparation remains an explicit backend call, never a fake NOP.
u64 request(GuestMemory& m, u32 caller, u32 descriptor, u32 token,
              u64 active, u64 incoming_v0, u32 gp, MediaCommandBackend* backend) {
    const u64 auxiliary = 0, kind = caller == 0x137598 ? 1 : 0;
    if (active == 0) {
        if (sx(descriptor) == sx(m.read_u32(loader + 0x5bc))) return incoming_v0;
        m.write_u32(loader + 0x5bc, descriptor);
        (void)source_strcpy(m, loader + 0xa74, token);
        m.write_u32(loader + 0x5c8, static_cast<u32>(auxiliary));
        m.write_u32(loader + 0x5d0, static_cast<u32>(kind));
        m.write_u32(loader + 0x5cc, 0);
        m.write_u32(loader + 0xdbc, 0);
        const u64 state_was_nonzero = m.read_u32(loader) != 0 ? 1 : 0;
        if (state_was_nonzero != 0) m.write_u32(loader, 0);
        m.write_u32(loader + 0x5c4, static_cast<u32>(state_was_nonzero));
        return state_was_nonzero;
    }
    if (permitted(m, gp) == 0) return 0; // Source branch at1376A0 actually returns here.
    const auto length = source_strlen(m, token);
    const auto bytes = m.bytes(token, length);
    MediaRequest event{caller, descriptor, token,
                       std::vector<std::uint8_t>(bytes.begin(), bytes.end()), auxiliary, active, kind};
    if (backend == nullptr) throw MissingMediaBackend(std::move(event));
    return backend->execute_active(m, event);
}

u64 begin(GuestMemory& m, u32 object, u32 token, u64 mode, u32 gp, MediaCommandBackend* backend) {
    const auto result = lookup(m, m.read_u32(object + 4), token);
    u64 value = result.found ? 1 : 0;
    if (mode == 1) value = request(m, 0x137578, result.descriptor, token, 1, value, gp, backend);
    else if (mode == 0) value = request(m, 0x137578, result.descriptor, token, 0, value, gp, backend);
    else if (!signed_less(mode, 2) && mode == 2)
        value = request(m, 0x137598, result.descriptor, token, 0, value, gp, backend);
    m.write_u32(object + 0x0c, result.group);
    return value;
}
u64 accept(GuestMemory& m, u32 object, u32 token, u32 gp, MediaCommandBackend* backend) {
    if (ready(m) == 0) return 0;
    (void)begin(m, object, token, 1, gp, backend);
    m.write_u32(object + 8, 2);
    return 1;
}

bool completion_ready(GuestMemory& m) { // 135618 -> 137318, 138BA8.
    return m.read_u32(loader) == 8 && busy(m) == 0 &&
           m.read_u32(loader + 0xea0) == m.read_u32(loader + 0xea4);
}

u64 select_scene(GuestMemory& m, u32 object, u32 token, u32 gp, MediaCommandBackend* backend) {
    const auto phase = m.read_u32(object + 8);
    if (phase == 0 || phase == 2) {
        if (ready(m)) {
            (void)begin(m, object, token, 0, gp, backend);
            m.write_u32(object + 8, 1);
        }
        return 0;
    }
    if (phase != 1 || !completion_ready(m)) return 0;
    m.write_u32(object + 0x10, m.read_u32(object + 0xc)); // 11E3B8
    if (!backend) throw std::runtime_error("0x00135660 requires a prepared scene backend");
    backend->finish_deferred(m);
    m.write_u32(object + 8, 0);
    return 1;
}
}

void tick_deferred_scene(GuestMemory& m, MediaCommandBackend& backend) {
    // 13EFF0 merely posts a playback request. The decoder task 13F208
    // consumes it on a later update, independently of the script opcode.
    if ((m.read_u32(0x236270) || m.read_u32(0x236268)) && !m.read_u32(0x23626c))
        backend.consume_image_start(m);
    if (!m.read_u32(loader) && !m.read_u32(loader + 0x5bc)) return;
    backend.step_deferred(m);
}

MissingMediaBackend::MissingMediaBackend(MediaRequest value)
    : std::runtime_error("1375d8 active preparation requires real media backend: 1384b0 assets; audio preservation/cleanup; 1378b0 preparation"),
      request(std::move(value)) {}

bool has_media_command(u32 entry) noexcept {
    switch (entry) {
    case 0x101a70: case 0x101aa8: case 0x101b10: case 0x101b58:
    case 0x11dac0: case 0x11dc40: case 0x11dcf8: case 0x11e310: case 0x127520:
    case 0x127e10: case 0x127c20: case 0x135618:
    case 0x137318: case 0x137350: case 0x1373b8: case 0x137568:
    case 0x137578: case 0x137598: return true;
    default: return false;
    }
}

u64 invoke_media_command(GuestMemory& m, u32 entry, u32 self,
                         u64 a1, u64 a2, u64 a3, u32 gp, MediaCommandBackend* backend) {
    switch (entry) {
    case 0x101a70: return little_word(m, self);
    case 0x101aa8: return little_half(m, self);
    case 0x101b10: return resource_hash(m, self);
    case 0x101b58: {
        const auto result = lookup(m, self, static_cast<u32>(a3));
        if (a1 != 0) m.write_u32(static_cast<u32>(a1), result.group);
        if (a2 != 0) m.write_u32(static_cast<u32>(a2), result.descriptor);
        return result.found ? 1 : 0;
    }
    case 0x11dac0: return sx(provider(m, gp));
    case 0x137318: return busy(m);
    case 0x137350: return ready(m);
    case 0x1373b8: return permitted(m, gp);
    case 0x137568: return m.read_u32(loader) != 0 ? 1 : 0;
    case 0x137578: case 0x137598:
        // For these source-void standalone calls incoming v0 is not part of this
        // ABI. The same-descriptor no-write path returns host placeholder0; calls
        // via11E310 preserve its actual incoming lookup v0 in request().
        return request(m, entry, self, static_cast<u32>(a1), a2, 0, gp, backend);
    case 0x11e310: return begin(m, self, static_cast<u32>(a1), a2, gp, backend);
    case 0x11dc40: return accept(m, self, static_cast<u32>(a1), gp, backend);
    case 0x11dcf8: return select_scene(m, self, static_cast<u32>(a1), gp, backend);
    case 0x135618: return completion_ready(m) ? 1 : 0;
    case 0x127e10: {
        const auto manager = static_cast<u32>(invoke_manager_ops(m, 0x10fb38, 0, 0, 0, 0, gp));
        m.write_u32(manager + 0x71c, 1); // 114A68(manager+330), including retries.
        return invoke_media_command(m, 0x127c20, self, a2, 0, 0, gp, backend);
    }
    case 0x127c20: case 0x127520: {
        const auto manager = static_cast<u32>(invoke_manager_ops(m, 0x10fb38, 0, 0, 0, 0, gp));
        const auto script = m.read_u32(manager + 0x38);
        const auto object = provider(m, gp);
        (void)invoke_script_data(m, 0x10d638, script, 0, 0);
        const auto token = static_cast<u32>(invoke_script_data(m, 0x10d680, script, 0, 0));
        const auto accepted = entry == 0x127520 ? accept(m, object, token, gp, backend)
                                                : select_scene(m, object, token, gp, backend);
        if (accepted != 0) return 0;
        (void)invoke_script_data(m, 0x10d700, script, a1, 0);
        return 1;
    }
    default: throw std::invalid_argument("media_command entry outside recovered source scope");
    }
}
}
