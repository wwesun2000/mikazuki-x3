#include "../core/guest_memory.hpp"
#include "../core/recovered.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
std::uint64_t read_integer(std::istream& stream, unsigned width) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < width; ++i) {
        int ch = stream.get();
        if (ch == std::char_traits<char>::eof()) throw std::runtime_error("Incomplete probe request");
        result |= std::uint64_t(std::uint8_t(ch)) << (8 * i);
    }
    return result;
}
void write_integer(std::ostream& stream, std::uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) stream.put(char(std::uint8_t(value >> (8 * i))));
}
std::uint32_t read32(std::istream& stream) { return std::uint32_t(read_integer(stream, 4)); }
void write32(std::ostream& stream, std::uint32_t value) { write_integer(stream, value, 4); }
std::uint32_t read_count(std::istream& stream) {
    auto count = read32(stream);
    if (count > 65536) throw std::runtime_error("Probe segment count exceeds its explicit limit");
    return count;
}
struct Range { std::uint32_t address; std::uint32_t length; };
}

// One request is isolated in a fresh guest memory image.
void run_one(std::istream& input, std::ostream& output) {
        std::array<char, 4> magic{};
        input.read(magic.data(), magic.size());
        auto version = read32(input);
        if (std::string(magic.data(), magic.size()) != "KX3I" || (version != 1 && version != 2))
            throw std::runtime_error("Unsupported probe request format");
        auto entry = read32(input);
        auto self = read32(input);
        auto a1 = read_integer(input, 8);
        auto a2 = read_integer(input, 8);
        auto a3 = version == 2 ? read_integer(input, 8) : 0;
        kx3::GuestMemory memory;
        auto count = read_count(input);
        for (std::uint32_t i = 0; i < count; ++i) {
            auto address = read32(input);
            auto length = read32(input);
            if (length > kx3::GuestMemory::size) throw std::runtime_error("Probe segment too large");
            std::vector<std::uint8_t> data(length);
            input.read(reinterpret_cast<char*>(data.data()), length);
            if (!input) throw std::runtime_error("Incomplete probe memory segment");
            memory.write_bytes(address, data);
        }
        std::vector<Range> observed;
        count = read_count(input);
        for (std::uint32_t i = 0; i < count; ++i) {
            auto address = read32(input);
            auto length = read32(input);
            (void)memory.bytes(address, length);
            observed.push_back({address, length});
        }
        if (input.peek() != std::char_traits<char>::eof()) throw std::runtime_error("Trailing probe input");
        auto result = kx3::invoke_recovered(memory, entry, self, a1, a2, a3);
        output.write("KX3O", 4);
        write32(output, 1);
        write_integer(output, result, 8);
        write32(output, std::uint32_t(observed.size()));
        for (auto range : observed) {
            write32(output, range.address);
            write32(output, range.length);
            auto bytes = memory.bytes(range.address, range.length);
            output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        }
        if (!output) throw std::runtime_error("Failed to write probe response");
}

// Binary probe protocol is documented in port/README.md. Batches avoid hundreds
// of Windows process launches; each case still receives a fresh zeroed image.
int main(int argc, char** argv) {
    try {
        const bool batch = argc == 4 && std::string(argv[1]) == "--batch";
        if (!batch && argc != 3) throw std::runtime_error("Usage: core_probe [--batch] request.bin response.bin");
        std::ifstream input(argv[batch ? 2 : 1], std::ios::binary);
        std::ofstream output(argv[batch ? 3 : 2], std::ios::binary | std::ios::trunc);
        if (!input || !output) throw std::runtime_error("Could not open probe files");
        if (!batch) {
            run_one(input, output);
            return 0;
        }
        std::array<char, 4> magic{};
        input.read(magic.data(), magic.size());
        if (std::string(magic.data(), magic.size()) != "KX3B" || read32(input) != 1)
            throw std::runtime_error("Unsupported probe batch format");
        auto count = read_count(input);
        output.write("KX3R", 4);
        write32(output, 1);
        write32(output, count);
        unsigned failures = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            auto length = read32(input);
            if (length > 64 * 1024 * 1024) throw std::runtime_error("Probe request exceeds batch frame limit");
            std::string payload(length, '\0');
            input.read(payload.data(), length);
            if (!input) throw std::runtime_error("Incomplete batch frame");
            std::istringstream source(payload, std::ios::binary);
            std::ostringstream target(std::ios::binary);
            std::uint32_t status = 0;
            try {
                run_one(source, target);
            } catch (const std::exception& error) {
                status = 2;
                ++failures;
                target.str(error.what());
            }
            auto result = target.str();
            write32(output, status);
            write32(output, std::uint32_t(result.size()));
            output.write(result.data(), result.size());
        }
        if (input.peek() != std::char_traits<char>::eof()) throw std::runtime_error("Trailing batch input");
        if (!output) throw std::runtime_error("Failed to write batch response");
        return failures == 0 ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
