#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <expected>
#include <bit>

namespace aether {

struct EthernetHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype; // network byte order
};
static_assert(sizeof(EthernetHeader) == 14);

struct Ipv4Header {
    uint8_t  version_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
static_assert(sizeof(Ipv4Header) == 20);

struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;     // network byte order
    uint16_t checksum;
};
static_assert(sizeof(UdpHeader) == 8);

struct ParsedPacket {
    EthernetHeader eth;
    Ipv4Header ip;
    UdpHeader udp;
    std::span<const uint8_t> payload;
};

enum class ParseError {
    TooShortForEthernet,
    NotIPv4,
    TooShortForIpv4,
    IhlOutOfRange,
    TooShortForIpPayload,
    NotUdp,
    TooShortForUdp,
    UdpLengthInconsistent,
    BadIpVersion,
    FragmentedPacket,
    IpLengthInconsistent,
};

template <typename T>
T bit_cast_from(std::span<const uint8_t> bytes) {
    std::array<uint8_t, sizeof(T)> buf{};
    for (std::size_t i = 0; i < sizeof(T); i++) buf[i] = bytes[i];
    return std::bit_cast<T>(buf);
}

// Parses an Ethernet + IPv4 + UDP header stack out of raw bytes, with an
// explicit bounds check before every read. This is the libFuzzer target
// in fuzz/packet_fuzz.cpp -- it is handed arbitrary, possibly truncated
// or adversarial byte buffers by construction, and must never read past
// `data`'s end regardless of what header fields themselves claim.
inline std::expected<ParsedPacket, ParseError> parse_udp_packet(std::span<const uint8_t> data) {
    if (data.size() < sizeof(EthernetHeader)) {
        return std::unexpected(ParseError::TooShortForEthernet);
    }
    EthernetHeader eth = bit_cast_from<EthernetHeader>(data);

    if (eth.ethertype != 0x0008) { // network-order 0x0800 (IPv4)
        return std::unexpected(ParseError::NotIPv4);
    }

    auto rest = data.subspan(sizeof(EthernetHeader));
    if (rest.size() < sizeof(Ipv4Header)) {
        return std::unexpected(ParseError::TooShortForIpv4);
    }
    Ipv4Header ip = bit_cast_from<Ipv4Header>(rest);

    if ((ip.version_ihl >> 4) != 4) {
        return std::unexpected(ParseError::BadIpVersion);
    }

    unsigned ihl_words = ip.version_ihl & 0x0F;
    std::size_t ihl_bytes = static_cast<std::size_t>(ihl_words) * 4;
    if (ihl_bytes < sizeof(Ipv4Header)) {
        return std::unexpected(ParseError::IhlOutOfRange);
    }
    if (rest.size() < ihl_bytes) {
        return std::unexpected(ParseError::TooShortForIpPayload);
    }
    if (ip.protocol != 17) { // UDP
        return std::unexpected(ParseError::NotUdp);
    }

    // flags_fragment is network order: 0x2000 = MF, low 13 bits = offset.
    // A fragment has no complete UDP header, so reject MF or offset != 0.
    uint16_t frag = static_cast<uint16_t>((ip.flags_fragment << 8) | (ip.flags_fragment >> 8));
    if ((frag & 0x3FFF) != 0) {
        return std::unexpected(ParseError::FragmentedPacket);
    }

    uint16_t total_host = static_cast<uint16_t>((ip.total_length << 8) | (ip.total_length >> 8));
    std::size_t ip_total = total_host;
    if (ip_total < ihl_bytes || ip_total > rest.size()) {
        return std::unexpected(ParseError::IpLengthInconsistent);
    }
    // The IP datagram ends at total_length; anything after is Ethernet padding.
    auto ip_payload = rest.subspan(ihl_bytes, ip_total - ihl_bytes);
    if (ip_payload.size() < sizeof(UdpHeader)) {
        return std::unexpected(ParseError::TooShortForUdp);
    }
    UdpHeader udp = bit_cast_from<UdpHeader>(ip_payload);

    uint16_t udp_len_host = static_cast<uint16_t>((udp.length << 8) | (udp.length >> 8));
    if (udp_len_host < sizeof(UdpHeader)) {
        return std::unexpected(ParseError::UdpLengthInconsistent);
    }
    std::size_t claimed_len = static_cast<std::size_t>(udp_len_host) - sizeof(UdpHeader);
    auto udp_payload = ip_payload.subspan(sizeof(UdpHeader));
    if (udp_payload.size() < claimed_len) {
        return std::unexpected(ParseError::UdpLengthInconsistent);
    }

    return ParsedPacket{eth, ip, udp, udp_payload.first(claimed_len)};
}

} // namespace aether
