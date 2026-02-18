#include "pcap_reader.h"
#include "util.h"

#include <stdexcept>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

// Magic numbers
static constexpr uint32_t PCAP_MAGIC_LE   = 0xa1b2c3d4;
static constexpr uint32_t PCAP_MAGIC_BE   = 0xd4c3b2a1;
static constexpr uint32_t PCAP_MAGIC_NS   = 0xa1b23c4d;
static constexpr uint32_t PCAP_MAGIC_NS_BE= 0x4d3cb2a1;
static constexpr uint32_t PCAPNG_SHB_MAGIC= 0x0a0d0d0a;
static constexpr uint32_t PCAPNG_BOM      = 0x1a2b3c4d;

// pcapng block types
static constexpr uint32_t BT_SHB = 0x0a0d0d0a;
static constexpr uint32_t BT_IDB = 0x00000001;
static constexpr uint32_t BT_EPB = 0x00000006;
static constexpr uint32_t BT_SPB = 0x00000003;

NativePcapReader::NativePcapReader(const std::string& path)
    : path_(path) {}

NativePcapReader::~NativePcapReader() {
    close();
}

void NativePcapReader::open() {
    if (opened_) return;

#ifdef _WIN32
    file_handle_ = CreateFileA(path_.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        file_handle_ = nullptr;
        throw std::runtime_error("Cannot open file: " + path_);
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file_handle_, &file_size)) {
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        throw std::runtime_error("Cannot get file size: " + path_);
    }
    map_size_ = static_cast<size_t>(file_size.QuadPart);

    if (map_size_ == 0) {
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        throw std::runtime_error("Empty file: " + path_);
    }

    map_handle_ = CreateFileMappingA(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map_handle_) {
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        throw std::runtime_error("Cannot create file mapping: " + path_);
    }

    map_base_ = static_cast<const uint8_t*>(MapViewOfFile(map_handle_, FILE_MAP_READ, 0, 0, 0));
    if (!map_base_) {
        CloseHandle(map_handle_);
        CloseHandle(file_handle_);
        map_handle_ = nullptr;
        file_handle_ = nullptr;
        throw std::runtime_error("Cannot map file: " + path_);
    }
#else
    fd_ = ::open(path_.c_str(), O_RDONLY);
    if (fd_ < 0) throw std::runtime_error("Cannot open file: " + path_);

    struct stat st;
    if (fstat(fd_, &st) < 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("Cannot stat file: " + path_);
    }
    map_size_ = static_cast<size_t>(st.st_size);

    if (map_size_ == 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("Empty file: " + path_);
    }

    map_base_ = static_cast<const uint8_t*>(
        mmap(nullptr, map_size_, PROT_READ, MAP_PRIVATE, fd_, 0));
    if (map_base_ == MAP_FAILED) {
        map_base_ = nullptr;
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("Cannot mmap file: " + path_);
    }
#endif

    offset_ = 0;
    opened_ = true;

    // Detect format from magic
    if (map_size_ < 4) throw std::runtime_error("File too small: " + path_);

    uint32_t magic = util::read_u32_le(map_base_);

    if (magic == PCAP_MAGIC_LE) {
        format_ = Format::PCAP;
        swap_endian_ = false;
        if (!parse_pcap_header())
            throw std::runtime_error("Invalid pcap header: " + path_);
    } else if (magic == PCAP_MAGIC_BE) {
        format_ = Format::PCAP;
        swap_endian_ = true;
        if (!parse_pcap_header())
            throw std::runtime_error("Invalid pcap header: " + path_);
    } else if (magic == PCAP_MAGIC_NS) {
        format_ = Format::PCAP_NS;
        swap_endian_ = false;
        if (!parse_pcap_header())
            throw std::runtime_error("Invalid pcap-ns header: " + path_);
    } else if (magic == PCAP_MAGIC_NS_BE) {
        format_ = Format::PCAP_NS;
        swap_endian_ = true;
        if (!parse_pcap_header())
            throw std::runtime_error("Invalid pcap-ns header: " + path_);
    } else if (magic == PCAPNG_SHB_MAGIC) {
        format_ = Format::PCAPNG;
        if (!parse_pcapng())
            throw std::runtime_error("Invalid pcapng header: " + path_);
    } else {
        throw std::runtime_error("Unknown file format (magic=" +
                                 std::to_string(magic) + "): " + path_);
    }
}

void NativePcapReader::close() {
    if (!opened_) return;

#ifdef _WIN32
    if (map_base_) { UnmapViewOfFile(map_base_); map_base_ = nullptr; }
    if (map_handle_) { CloseHandle(map_handle_); map_handle_ = nullptr; }
    if (file_handle_) { CloseHandle(file_handle_); file_handle_ = nullptr; }
#else
    if (map_base_) { munmap(const_cast<uint8_t*>(map_base_), map_size_); map_base_ = nullptr; }
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
#endif

    opened_ = false;
    map_size_ = 0;
    offset_ = 0;
}

const uint8_t* NativePcapReader::peek(size_t n) const {
    if (offset_ + n > map_size_) return nullptr;
    return map_base_ + offset_;
}

void NativePcapReader::advance(size_t n) {
    offset_ += n;
    if (offset_ > map_size_) offset_ = map_size_;
}

size_t NativePcapReader::remaining() const {
    return (offset_ < map_size_) ? (map_size_ - offset_) : 0;
}

uint16_t NativePcapReader::read_u16() {
    auto p = peek(2);
    if (!p) throw std::runtime_error("Unexpected EOF");
    uint16_t v = swap_endian_ ? util::read_u16_be(p) : util::read_u16_le(p);
    advance(2);
    return v;
}

uint32_t NativePcapReader::read_u32() {
    auto p = peek(4);
    if (!p) throw std::runtime_error("Unexpected EOF");
    uint32_t v = swap_endian_ ? util::read_u32_be(p) : util::read_u32_le(p);
    advance(4);
    return v;
}

uint64_t NativePcapReader::read_u64() {
    auto p = peek(8);
    if (!p) throw std::runtime_error("Unexpected EOF");
    uint64_t v;
    if (swap_endian_) {
        v = (static_cast<uint64_t>(util::read_u32_be(p)) << 32) | util::read_u32_be(p + 4);
    } else {
        v = util::read_u64_le(p);
    }
    advance(8);
    return v;
}

// ── pcap format ──

bool NativePcapReader::parse_pcap_header() {
    if (remaining() < 24) return false;
    advance(4); // skip magic (already read)
    /*uint16_t ver_major =*/ read_u16();
    /*uint16_t ver_minor =*/ read_u16();
    advance(8); // thiszone + sigfigs
    /*uint32_t snaplen =*/ read_u32();
    link_type_ = read_u32();
    return true;
}

std::optional<RawPacket> NativePcapReader::read_pcap_packet() {
    if (remaining() < 16) return std::nullopt;

    uint32_t ts_sec  = read_u32();
    uint32_t ts_usec = read_u32();
    uint32_t caplen  = read_u32();
    uint32_t wirelen = read_u32();

    if (remaining() < caplen) return std::nullopt;

    auto p = peek(caplen);
    if (!p) return std::nullopt;

    double ts;
    if (format_ == Format::PCAP_NS) {
        ts = static_cast<double>(ts_sec) + static_cast<double>(ts_usec) * 1e-9;
    } else {
        ts = static_cast<double>(ts_sec) + static_cast<double>(ts_usec) * 1e-6;
    }

    std::vector<uint8_t> data(p, p + caplen);
    advance(caplen);

    return RawPacket{ts, std::move(data), caplen, wirelen, link_type_};
}

// ── pcapng format ──

bool NativePcapReader::parse_pcapng() {
    // Read SHB
    if (!read_pcapng_shb()) return false;

    // Read blocks until we find at least one IDB, then stop before first packet
    while (remaining() >= 8) {
        auto saved = offset_;
        auto p = peek(4);
        if (!p) break;
        uint32_t block_type = swap_endian_ ? util::read_u32_be(p) : util::read_u32_le(p);

        if (block_type == BT_IDB) {
            if (!read_pcapng_idb()) return false;
        } else {
            // Reached a non-IDB block (likely EPB) — stop header parsing
            offset_ = saved;
            break;
        }
    }

    if (iface_link_types_.empty()) return false;
    link_type_ = iface_link_types_[0];
    return true;
}

bool NativePcapReader::read_pcapng_shb() {
    if (remaining() < 12) return false;

    uint32_t block_type = util::read_u32_le(map_base_ + offset_);
    if (block_type != BT_SHB) return false;
    advance(4);

    // Block total length
    uint32_t block_len_le = util::read_u32_le(map_base_ + offset_);
    uint32_t block_len_be = util::read_u32_be(map_base_ + offset_);
    advance(4);

    // Byte order magic
    auto p = peek(4);
    if (!p) return false;
    uint32_t bom = util::read_u32_le(p);
    if (bom == PCAPNG_BOM) {
        swap_endian_ = false;
    } else if (bom == 0x4d3c2b1a) {
        swap_endian_ = true;
    } else {
        return false;
    }

    uint32_t block_len = swap_endian_ ? block_len_be : block_len_le;

    // Skip rest of SHB (version, section length, options, trailing length)
    // We already consumed 8 bytes (type + length), skip to end
    size_t shb_start = offset_ - 8;
    offset_ = shb_start + block_len;
    return true;
}

bool NativePcapReader::read_pcapng_idb() {
    if (remaining() < 8) return false;

    advance(4); // block type (already checked)
    uint32_t block_len = read_u32();
    if (block_len < 20) return false;

    uint16_t lt = read_u16();
    /*uint16_t reserved =*/ read_u16();
    /*uint32_t snaplen =*/ read_u32();

    iface_link_types_.push_back(lt);

    // Skip to end of block (block_len includes type+length fields)
    size_t idb_start = offset_ - 16; // type(4) + len(4) + lt(2) + reserved(2) + snaplen(4)
    offset_ = idb_start + block_len;
    return true;
}

std::optional<RawPacket> NativePcapReader::read_pcapng_block() {
    while (remaining() >= 12) {
        auto p = peek(4);
        if (!p) return std::nullopt;
        uint32_t block_type = swap_endian_ ? util::read_u32_be(p) : util::read_u32_le(p);
        advance(4);

        uint32_t block_len = read_u32();
        if (block_len < 12) return std::nullopt;

        size_t block_start = offset_ - 8;
        size_t block_end = block_start + block_len;

        if (block_end > map_size_) return std::nullopt;

        if (block_type == BT_EPB) {
            // Enhanced Packet Block
            if (remaining() < 20) return std::nullopt;

            uint32_t iface_id = read_u32();
            uint32_t ts_hi = read_u32();
            uint32_t ts_lo = read_u32();
            uint32_t caplen = read_u32();
            uint32_t wirelen = read_u32();

            if (remaining() < caplen) { offset_ = block_end; continue; }

            auto pkt_data = peek(caplen);
            if (!pkt_data) { offset_ = block_end; continue; }

            // Timestamp: 64-bit value in interface-specific resolution (default: microseconds)
            uint64_t ts_raw = (static_cast<uint64_t>(ts_hi) << 32) | ts_lo;
            double ts = static_cast<double>(ts_raw) * 1e-6;

            uint32_t lt = (iface_id < iface_link_types_.size())
                          ? iface_link_types_[iface_id]
                          : link_type_;

            std::vector<uint8_t> data(pkt_data, pkt_data + caplen);
            offset_ = block_end;

            return RawPacket{ts, std::move(data), caplen, wirelen, lt};
        } else if (block_type == BT_IDB) {
            // Interface Description Block mid-stream
            if (remaining() >= 8) {
                uint16_t lt = read_u16();
                iface_link_types_.push_back(lt);
            }
            offset_ = block_end;
        } else {
            // Skip unknown block types
            offset_ = block_end;
        }
    }
    return std::nullopt;
}

std::optional<RawPacket> NativePcapReader::next() {
    if (!opened_) throw std::runtime_error("Reader not opened");

    if (format_ == Format::PCAPNG) {
        return read_pcapng_block();
    } else {
        return read_pcap_packet();
    }
}

// ── Zero-copy view methods ──

std::optional<RawPacketView> NativePcapReader::read_pcap_packet_view() {
    if (remaining() < 16) return std::nullopt;

    uint32_t ts_sec  = read_u32();
    uint32_t ts_usec = read_u32();
    uint32_t caplen  = read_u32();
    uint32_t wirelen = read_u32();

    if (remaining() < caplen) return std::nullopt;

    auto p = peek(caplen);
    if (!p) return std::nullopt;

    double ts;
    if (format_ == Format::PCAP_NS) {
        ts = static_cast<double>(ts_sec) + static_cast<double>(ts_usec) * 1e-9;
    } else {
        ts = static_cast<double>(ts_sec) + static_cast<double>(ts_usec) * 1e-6;
    }

    advance(caplen);
    return RawPacketView{ts, p, caplen, wirelen, link_type_};
}

std::optional<RawPacketView> NativePcapReader::read_pcapng_block_view() {
    while (remaining() >= 12) {
        auto p = peek(4);
        if (!p) return std::nullopt;
        uint32_t block_type = swap_endian_ ? util::read_u32_be(p) : util::read_u32_le(p);
        advance(4);

        uint32_t block_len = read_u32();
        if (block_len < 12) return std::nullopt;

        size_t block_start = offset_ - 8;
        size_t block_end = block_start + block_len;

        if (block_end > map_size_) return std::nullopt;

        if (block_type == BT_EPB) {
            if (remaining() < 20) return std::nullopt;

            uint32_t iface_id = read_u32();
            uint32_t ts_hi = read_u32();
            uint32_t ts_lo = read_u32();
            uint32_t caplen = read_u32();
            uint32_t wirelen = read_u32();

            if (remaining() < caplen) { offset_ = block_end; continue; }

            auto pkt_data = peek(caplen);
            if (!pkt_data) { offset_ = block_end; continue; }

            uint64_t ts_raw = (static_cast<uint64_t>(ts_hi) << 32) | ts_lo;
            double ts = static_cast<double>(ts_raw) * 1e-6;

            uint32_t lt = (iface_id < iface_link_types_.size())
                          ? iface_link_types_[iface_id]
                          : link_type_;

            offset_ = block_end;
            return RawPacketView{ts, pkt_data, caplen, wirelen, lt};
        } else if (block_type == BT_IDB) {
            if (remaining() >= 8) {
                uint16_t lt = read_u16();
                iface_link_types_.push_back(lt);
            }
            offset_ = block_end;
        } else {
            offset_ = block_end;
        }
    }
    return std::nullopt;
}

std::optional<RawPacketView> NativePcapReader::next_view() {
    if (!opened_) throw std::runtime_error("Reader not opened");

    if (format_ == Format::PCAPNG) {
        return read_pcapng_block_view();
    } else {
        return read_pcap_packet_view();
    }
}
