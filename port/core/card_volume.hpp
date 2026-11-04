#pragma once
#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace kx3 {
class CardWriteError : public std::system_error {
public:
    explicit CardWriteError(const std::system_error& failure):std::system_error(failure){}
};
struct CardFileEntry {
    std::string name;
    bool directory;
    std::uint32_t size;
    std::int64_t modified;
};
// A formatted native card in port 0. Adapter keys are the paths emitted by
// the game, relative to the card root. Port 1 has no card inserted.
class CardVolume {
public:
    void mount(std::filesystem::path directory);
    std::vector<CardFileEntry> enumerate(const std::string& pattern) const;
    const std::vector<std::uint8_t>* read(const std::string& key) const;
    std::uint32_t free_clusters() const;
    bool stage_file(std::string key,std::span<const std::uint8_t> bytes,bool create);
    void commit_writes(bool preserve_existing=false);
    void discard_writes() noexcept {pending_.clear();}
    void set_icon(std::string name,std::vector<std::uint8_t> bytes);
    const std::vector<std::uint8_t>& icon(const std::string& name) const;
private:
    struct File {std::vector<std::uint8_t> bytes; std::int64_t modified;};
    using Files=std::map<std::string,File>;
    static Files read_volume(const std::filesystem::path&);
    std::filesystem::path root_;
    Files files_,pending_;
    std::map<std::string,std::vector<std::uint8_t>> icons_;
};
}
