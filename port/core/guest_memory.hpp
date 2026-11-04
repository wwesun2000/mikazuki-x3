#pragma once

#include <cstddef>
#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>
#include <utility>

namespace kx3 {

// Explicit PS2 little-endian, 32-bit guest addresses. Never cast guest addresses
// to host pointers. This is the core's RAM image, not a hardware/PS2 emulator.
class GuestMemory {
public:
    static constexpr std::size_t size = 32 * 1024 * 1024;
    GuestMemory() : storage_(size, 0) {}
    GuestMemory(const GuestMemory&) = delete;
    GuestMemory& operator=(const GuestMemory&) = delete;
    GuestMemory& operator=(GuestMemory&&) = delete;
    // Preserve a valid zeroed 32 MiB moved-from object. Active transactions may
    // never be moved; their RAII guard still refers to the original owner.
    GuestMemory(GuestMemory&& other) : GuestMemory() { replace_contents(std::move(other)); }
    [[nodiscard]] bool transaction_active() const noexcept { return transaction_; }
    void replace_contents(GuestMemory&& other) {
        if (transaction_ || other.transaction_ || budgeted_ || other.budgeted_)
            throw std::logic_error("Cannot replace memory during guest execution");
        storage_.swap(other.storage_);
    }
    class AccessBudget {
    public:
        explicit AccessBudget(GuestMemory& memory, std::size_t limit) : memory_(memory) {
            if (memory_.budgeted_ || !limit) throw std::logic_error("Invalid/nested native access budget");
            memory_.budgeted_=true; memory_.remaining_accesses_=limit;
        }
        AccessBudget(const AccessBudget&)=delete;
        AccessBudget& operator=(const AccessBudget&)=delete;
        ~AccessBudget() { memory_.budgeted_=false; }
    private:
        GuestMemory& memory_;
    };

    // Host safety boundary, not an invented game instruction. A native step
    // which reaches an unrecovered dependency must not consume script data or
    // leave half-applied save/progress fields. External effects must be queued
    // separately and published only after commit.
    class Transaction {
    public:
        explicit Transaction(GuestMemory& memory) : memory_(memory) { memory_.begin(); }
        Transaction(const Transaction&) = delete;
        Transaction& operator=(const Transaction&) = delete;
        ~Transaction() { if (active_) memory_.rollback(); }
        void commit() {
            if (!active_) throw std::logic_error("Guest transaction already completed");
            memory_.finish();
            active_ = false;
        }
    private:
        GuestMemory& memory_;
        bool active_ = true;
    };

    [[nodiscard]] std::span<const std::uint8_t> bytes(std::uint32_t address, std::size_t length) const {
        check(address, length);
        return {storage_.data() + address, length};
    }
    void write_bytes(std::uint32_t address, std::span<const std::uint8_t> data) {
        check(address, data.size());
        remember(address, data.size());
        for (std::size_t i = 0; i < data.size(); ++i) storage_[address + i] = data[i];
    }
    [[nodiscard]] std::uint8_t read_u8(std::uint32_t address) const {
        check(address, 1);
        return storage_[address];
    }
    [[nodiscard]] std::uint16_t read_u16(std::uint32_t address) const {
        auto s = bytes(address, 2);
        return std::uint16_t(s[0]) | (std::uint16_t(s[1]) << 8);
    }
    [[nodiscard]] std::uint32_t read_u32(std::uint32_t address) const {
        auto s = bytes(address, 4);
        return std::uint32_t(s[0]) | (std::uint32_t(s[1]) << 8) |
               (std::uint32_t(s[2]) << 16) | (std::uint32_t(s[3]) << 24);
    }
    void write_u8(std::uint32_t address, std::uint8_t value) {
        check(address, 1);
        remember(address, 1);
        storage_[address] = value;
    }
    void write_u16(std::uint32_t address, std::uint16_t value) {
        check(address, 2);
        remember(address, 2);
        for (unsigned i = 0; i < 2; ++i) storage_[address + i] = std::uint8_t(value >> (8 * i));
    }
    void write_u32(std::uint32_t address, std::uint32_t value) {
        check(address, 4);
        remember(address, 4);
        for (unsigned i = 0; i < 4; ++i) storage_[address + i] = std::uint8_t(value >> (8 * i));
    }

private:
    static constexpr std::size_t page_size = 4096;
    struct PageBackup { std::size_t index; std::array<std::uint8_t, page_size> bytes; };
    std::vector<std::uint8_t> storage_;
    std::vector<PageBackup> journal_;
    std::array<bool, size / page_size> remembered_{};
    bool transaction_ = false;
    bool budgeted_ = false;
    mutable std::size_t remaining_accesses_ = 0;
    void begin() {
        if (transaction_) throw std::logic_error("Nested guest transactions are unsupported");
        transaction_ = true;
    }
    void remember(std::uint32_t address, std::size_t length) {
        if (!transaction_ || length == 0) return;
        const std::size_t last = (std::size_t(address) + length - 1) / page_size;
        for (std::size_t page = address / page_size; page <= last; ++page) {
            if (remembered_[page]) continue;
            PageBackup backup{page, {}};
            std::copy_n(storage_.begin() + page * page_size, page_size, backup.bytes.begin());
            journal_.push_back(backup);
            remembered_[page] = true;
        }
    }
    void finish() noexcept {
        for (const auto& page : journal_) remembered_[page.index] = false;
        journal_.clear();
        transaction_ = false;
    }
    void rollback() noexcept {
        for (const auto& page : journal_)
            std::copy(page.bytes.begin(), page.bytes.end(), storage_.begin() + page.index * page_size);
        finish();
    }
    void check(std::uint32_t address, std::size_t length) const {
        if (address > size || length > size - address)
            throw std::out_of_range("Guest RAM access outside the explicitly supported 32 MiB image");
        if (budgeted_) {
            if (!remaining_accesses_) throw std::runtime_error("Native step memory-access budget exhausted");
            --remaining_accesses_;
        }
    }
};

} // namespace kx3
