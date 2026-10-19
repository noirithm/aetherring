#include "proto/packet_header.hpp"
#include <gtest/gtest.h>
#include <vector>

using namespace aether;

static std::vector<uint8_t> make_valid_packet() {
    std::vector<uint8_t> pkt;
    // Ethernet: 6 dst + 6 src + ethertype 0x0800 (network order: 0x08,0x00)
    pkt.insert(pkt.end(), 12, 0xAA);
    pkt.push_back(0x08);
    pkt.push_back(0x00);
    // IPv4: version/ihl=0x45 (ihl=5 -> 20 bytes), rest mostly zero, protocol=17 (UDP)
    pkt.push_back(0x45);
    pkt.insert(pkt.end(), 8, 0x00);
    pkt.push_back(17); // protocol
    pkt.insert(pkt.end(), 10, 0x00); // checksum + src_ip + dst_ip (pad to 20 total)
    // UDP: src_port, dst_port, length (network order: 12 = 0x000C), checksum
    pkt.insert(pkt.end(), 4, 0x00);
    pkt.push_back(0x00);
    pkt.push_back(0x0C); // length = 12 (8 header + 4 payload), network order
    pkt.insert(pkt.end(), 2, 0x00);
    // 4 bytes of UDP payload
    pkt.insert(pkt.end(), {0xDE, 0xAD, 0xBE, 0xEF});
    return pkt;
}

TEST(PacketParser, ParsesValidPacket) {
    auto pkt = make_valid_packet();
    auto result = parse_udp_packet(pkt);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ip.protocol, 17);
    ASSERT_EQ(result->payload.size(), 4u);
    EXPECT_EQ(result->payload[0], 0xDE);
}

TEST(PacketParser, RejectsTruncatedEthernet) {
    std::vector<uint8_t> pkt = {0x01, 0x02, 0x03};
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::TooShortForEthernet);
}

TEST(PacketParser, RejectsTruncatedAfterEachLayer) {
    auto full = make_valid_packet();
    // truncate at every possible length and confirm it's either a clean
    // error or a clean success -- never a crash (that property is what
    // the fuzzer in step 3 checks far more exhaustively than this can).
    for (std::size_t len = 0; len <= full.size(); len++) {
        std::span<const uint8_t> truncated(full.data(), len);
        auto result = parse_udp_packet(truncated);
        (void)result; // just must not crash/UB; ASan (step 3) is the real check
    }
    SUCCEED();
}

TEST(PacketParser, RejectsBadEthertype) {
    auto pkt = make_valid_packet();
    pkt[12] = 0x86; pkt[13] = 0xDD; // IPv6 ethertype instead
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::NotIPv4);
}

TEST(PacketParser, RejectsInconsistentUdpLength) {
    auto pkt = make_valid_packet();
    pkt[38] = 0xFF; // claim a huge UDP length that the buffer can't satisfy
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::UdpLengthInconsistent);
}
