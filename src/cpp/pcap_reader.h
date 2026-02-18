#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <tuple>

// Packet tuple: (timestamp, data, caplen, wirelen, link_type)
using RawPacket = std::tuple<double, std::vector<uint8_t>, uint32_t, uint32_t, uint32_t>;

// Zero-copy view into mmap'd packet data (valid while reader is open)
struct RawPacketView {
    double timestamp;
    const uint8_t* data;   // pointer into mmap'd buffer — no copy
    uint32_t caplen;
    uint32_t wirelen;
    uint32_t link_type;
};

class NativePcapReader {
public:
    explicit NativePcapReader(const std::string& path);
    ~NativePcapReader();

    NativePcapReader(const NativePcapReader&) = delete;
    NativePcapReader& operator=(const NativePcapReader&) = delete;

    void open();
    void close();
    std::optional<RawPacket> next();
    uint32_t link_type() const { return link_type_; }

    // Zero-copy: returns pointer into mmap'd buffer (no vector allocation)
    std::optional<RawPacketView> next_view();

private:
    // pcap global header parsing
    bool parse_pcap_header();
    std::optional<RawPacket> read_pcap_packet();

    // pcapng parsing
    bool parse_pcapng();
    std::optional<RawPacket> read_pcapng_block();
    bool read_pcapng_shb();
    bool read_pcapng_idb();

    // Zero-copy variants (return pointer into mmap)
    std::optional<RawPacketView> read_pcap_packet_view();
    std::optional<RawPacketView> read_pcapng_block_view();

    std::string path_;
    bool opened_ = false;

    // Memory-mapped file
    const uint8_t* map_base_ = nullptr;
    size_t map_size_ = 0;
    size_t offset_ = 0;

    // Platform-specific handles
#ifdef _WIN32
    void* file_handle_ = nullptr;   // HANDLE
    void* map_handle_ = nullptr;    // HANDLE
#else
    int fd_ = -1;
#endif

    // File format
    enum class Format { PCAP, PCAP_NS, PCAPNG };
    Format format_ = Format::PCAP;
    bool swap_endian_ = false;
    uint32_t link_type_ = 0;

    // pcapng state
    uint32_t pcapng_section_endian_ = 0;
    // Per-interface link types for pcapng
    std::vector<uint32_t> iface_link_types_;

    // Helper: read from mapped memory
    const uint8_t* peek(size_t n) const;
    void advance(size_t n);
    size_t remaining() const;

    uint16_t read_u16();
    uint32_t read_u32();
    uint64_t read_u64();
};
