#include "../core/font_cursor.hpp"
#include "../core/guest_memory.hpp"
#include <iostream>
#include <string>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::invalid_argument("Expected the source a0 register");
        const auto font = std::stoull(argv[1], nullptr, 0);
        if (font > UINT32_MAX) throw std::out_of_range("Font pointer outside guest address space");
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
#endif
        kx3::GuestMemory memory;
        std::vector<std::uint8_t> ram(memory.size);
        std::cin.read(reinterpret_cast<char*>(ram.data()), ram.size());
        if (!std::cin || std::cin.peek() != EOF) throw std::runtime_error("Expected a complete RAM fixture");
        memory.write_bytes(0, ram);
        kx3::GuestMemory::Transaction transaction(memory);
        kx3::initialize_font_cursor(memory, static_cast<std::uint32_t>(font));
        transaction.commit();
        const auto result = memory.bytes(0, memory.size);
        std::cout.write(reinterpret_cast<const char*>(result.data()), result.size());
        if (!std::cout) throw std::runtime_error("Failed to write complete RAM");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
