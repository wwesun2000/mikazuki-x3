#include "../core/guest_memory.hpp"
#include "../core/runtime.hpp"
#include "../core/save.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main(int argc, char** argv) {
    try {
        kx3::GuestMemory m;
        m.write_u32(4094, 0x12345678);
        const std::vector<std::uint8_t> initial(m.bytes(0, 16384).begin(), m.bytes(0, 16384).end());
        {
            kx3::GuestMemory::Transaction t(m);
            m.write_u8(0, 1);
            m.write_u16(4095, 0xabcd);
            m.write_u32(8190, 0x11223344);
            std::vector<std::uint8_t> data(6000, 0xf1);
            m.write_bytes(8000, data);
        }
        require(std::equal(initial.begin(), initial.end(), m.bytes(0, initial.size()).begin()), "Cross-page rollback failed");
        {
            kx3::GuestMemory::Transaction t(m);
            m.write_u32(4094, 7);
            t.commit();
        }
        require(m.read_u32(4094) == 7, "Committed write lost");
        try {
            kx3::GuestMemory::Transaction t(m);
            m.write_u32(4094, 9);
            m.write_u32(kx3::GuestMemory::size - 1, 0);
            throw std::runtime_error("Expected bounds failure");
        } catch (const std::out_of_range&) {}
        require(m.read_u32(4094) == 7, "Bounds exception rollback failed");
        {
            kx3::GuestMemory::Transaction t(m);
            m.write_u32(4094, 11);
            bool rejected = false;
            try { kx3::GuestMemory::Transaction nested(m); }
            catch (const std::logic_error&) { rejected = true; }
            require(rejected, "Nested transaction silently accepted");
        }
        require(m.read_u32(4094) == 7, "Nested rejection broke outer rollback");
        bool active_move_rejected=false;
        {
            kx3::GuestMemory::Transaction t(m);
            m.write_u32(4094,13);
            try {kx3::GuestMemory moved(std::move(m));}
            catch(const std::logic_error&) {active_move_rejected=true;}
        }
        require(active_move_rejected && m.read_u32(4094)==7,"Moving active memory bypassed rollback");
        {
            kx3::GuestMemory moved(std::move(m));
            require(m.read_u32(4094)==0 && moved.read_u32(4094)==7,"Moved-from RAM is invalid");
            m.replace_contents(std::move(moved));
        }
        bool budget_exhausted=false;
        try {
            kx3::GuestMemory::AccessBudget b(m,3);
            kx3::GuestMemory::Transaction t(m);
            m.write_u32(4094,21);
            for(int i=0;i<4;++i) (void)m.read_u8(0);
        } catch(const std::runtime_error&) {budget_exhausted=true;}
        require(budget_exhausted && m.read_u32(4094)==7,"Execution budget failure did not rollback");

        // Original default dispatcher state, with a deliberately unrecovered
        // admitted handler. Its cursor advance must survive success only.
        const std::uint32_t manager=0x01000000, script=0x01001000, context=0x01002000;
        const std::uint32_t context_vt=0x01003000, handler=0x01004000, handler_vt=0x01005000;
        const std::uint32_t code=0x01006000;
        m.write_u32(manager+0x38, script);
        m.write_u32(manager+0x40, context);
        m.write_u32(context, context_vt);
        m.write_u32(context_vt+4, 0x00120308);
        m.write_u32(context_vt+8, 0x001203e0);
        m.write_u32(manager+0x5c+5*4, handler);
        m.write_u32(handler, handler_vt);
        m.write_u32(handler_vt+0x3c, 0x001ffff0);
        m.write_u32(0x00206010, 5);
        m.write_u8(code, 5);
        m.write_u32(script+8, 0x01007000);
        m.write_u32(0x01007000+0x430, code);
        m.write_u32(script+0xd8, code);
        bool missing = false;
        try { (void)kx3::step_context_atomic(m, manager); }
        catch (const std::runtime_error& e) {
            missing = std::string(e.what()).find("001ffff0") != std::string::npos;
        }
        require(missing, "Missing handler not reported precisely");
        require(m.read_u32(script+0xd8) == code, "Failed step consumed opcode");
        m.write_u32(handler_vt+0x3c, 0x001227f0); // Actual zero-return source wrapper.
        require(kx3::step_context_atomic(m, manager) == 0, "Source zero wrapper failed");
        require(m.read_u32(script+0xd8) == code+1, "Successful step did not consume opcode");
        // A valid-address but cyclic vtable must fail before exhausting host stack.
        m.write_u32(context_vt+4,0x001203e0);
        m.write_u32(manager,context_vt);
        m.write_u32(context_vt+0x3c,0x001203e0);
        bool cycle_rejected=false;
        try {(void)kx3::step_context_atomic(m,manager);}
        catch(const std::runtime_error& e) {cycle_rejected=std::string(e.what()).find("depth limit")!=std::string::npos;}
        require(cycle_rejected,"Cyclic virtual dispatch was not bounded");
        m.write_u32(context_vt+4,0x00120308);
        m.write_u32(manager+0x2b4,1);
        m.write_u8(code+1,0x21);
        m.write_u8(code+2,0x03);
        require(kx3::step_script_atomic(m,manager)==0 && m.read_u32(script+0xd8)==code+3
                && m.read_u32(manager+0x2b4)==0,"Inline text did not consume its skip and terminator in the same pump");
        kx3::CoreCheckpoint state;
        state.memory.replace_contents(std::move(m));
        state.manager=manager;
        state.logical_tick=0x123456789abcdef0ull;
        kx3::SaveIdentity identity;
        identity.executable_sha256.fill(0x3b);
        identity.assets_sha256.fill(0xa7);
        const auto encoded=kx3::encode_checkpoint(state,identity);
        auto restored=kx3::decode_checkpoint(encoded,identity);
        require(restored.manager==manager && restored.logical_tick==state.logical_tick, "Checkpoint metadata lost");
        require(std::equal(state.memory.bytes(0,kx3::GuestMemory::size).begin(),
                           state.memory.bytes(0,kx3::GuestMemory::size).end(),
                           restored.memory.bytes(0,kx3::GuestMemory::size).begin()), "Checkpoint changed original state");
        auto corrupted=encoded;
        corrupted[corrupted.size()/2]^=1;
        bool corrupt_rejected=false, identity_rejected=false, truncated_rejected=false;
        try { (void)kx3::decode_checkpoint(corrupted,identity); } catch(const std::runtime_error&) {corrupt_rejected=true;}
        auto wrong_identity=identity; wrong_identity.assets_sha256[0]^=1;
        try { (void)kx3::decode_checkpoint(encoded,wrong_identity); } catch(const std::runtime_error&) {identity_rejected=true;}
        try { (void)kx3::decode_checkpoint(std::span(encoded).first(encoded.size()-1),identity); }
        catch(const std::runtime_error&) {truncated_rejected=true;}
        require(corrupt_rejected && identity_rejected && truncated_rejected, "Invalid checkpoint accepted");
        bool partial_rejected=false;
        {
            kx3::GuestMemory::Transaction t(state.memory);
            state.memory.write_u8(code,0xff);
            try { (void)kx3::encode_checkpoint(state,identity); }
            catch(const std::runtime_error&) {partial_rejected=true;}
        }
        require(partial_rejected, "Partial execution checkpoint allowed");
        require(argc==2,"Supply project-owned isolated save test directory");
        const std::filesystem::path directory=argv[1];
        require(!std::filesystem::exists(directory),"Save test directory must be new");
        std::filesystem::create_directories(directory);
        const auto slot=directory/"slot.kx3save";
        kx3::write_checkpoint_atomic(slot,state,identity);
        state.logical_tick=9;
        kx3::write_checkpoint_atomic(slot,state,identity);
        require(kx3::read_checkpoint(slot,identity).logical_tick==9,"Atomic slot replacement failed");
        auto pending=slot; pending+=".pending";
        {std::ofstream blocker(pending); blocker<<"owned test blocker";}
        bool collision_rejected=false;
        state.logical_tick=10;
        try {kx3::write_checkpoint_atomic(slot,state,identity);}
        catch(const std::system_error&) {collision_rejected=true;}
        require(collision_rejected && kx3::read_checkpoint(slot,identity).logical_tick==9,"Failed save changed existing slot");
        require(std::filesystem::file_size(pending)==18,"Another writer's temporary was changed");
        std::filesystem::remove(pending);
#ifdef _WIN32
        HANDLE held=CreateFileW(slot.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        require(held!=INVALID_HANDLE_VALUE,"Could not create controlled slot sharing conflict");
        bool replace_rejected=false;
        try {kx3::write_checkpoint_atomic(slot,state,identity);}
        catch(const std::system_error&) {replace_rejected=true;}
        CloseHandle(held);
        require(replace_rejected && kx3::read_checkpoint(slot,identity).logical_tick==9 && !std::filesystem::exists(pending),
                "Actual Windows replace failure changed slot or left owned temporary");
#endif
        std::cout << "Host contracts passed: rollback/commit/bounds, real dispatcher rollback, sparse checkpoint round-trip, integrity/identity rejection, atomic disk replacement and failure preservation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
