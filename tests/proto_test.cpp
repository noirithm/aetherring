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
    pkt.insert(pkt.end(), {0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 64}); // dscp, total_len=32, id, flags/frag, ttl
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

TEST(PacketParser, RejectsBadIpVersion) {
    auto pkt = make_valid_packet();
    pkt[14] = 0x65; // version 6, ihl 5
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::BadIpVersion);
}

TEST(PacketParser, RejectsNonFirstFragment) {
    auto pkt = make_valid_packet();
    pkt[14 + 7] = 0x05; // fragment offset = 5
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::FragmentedPacket);
}

TEST(PacketParser, RejectsMoreFragmentsFlag) {
    auto pkt = make_valid_packet();
    pkt[14 + 6] = 0x20; // MF set, offset 0
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::FragmentedPacket);
}

TEST(PacketParser, ParsesWithDontFragmentFlag) {
    auto pkt = make_valid_packet();
    pkt[14 + 6] = 0x40; // DF is fine
    EXPECT_TRUE(parse_udp_packet(pkt).has_value());
}

TEST(PacketParser, RejectsIpTotalLengthBelowHeader) {
    auto pkt = make_valid_packet();
    pkt[14 + 3] = 0x00; // total_length = 0
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::IpLengthInconsistent);
}

TEST(PacketParser, RejectsIpTotalLengthPastBuffer) {
    auto pkt = make_valid_packet();
    pkt[14 + 3] = 0xFF; // total_length = 255, only 32 bytes present
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::IpLengthInconsistent);
}

TEST(PacketParser, UdpLengthCannotReachIntoEthernetPadding) {
    auto pkt = make_valid_packet();
    pkt.insert(pkt.end(), 8, 0x00); // padding after the IP datagram
    pkt[39] = 0x14;                 // udp length 20 -> would read into the padding
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::UdpLengthInconsistent);
}

TEST(PacketParser, AcceptsPaddingAfterValidDatagram) {
    auto pkt = make_valid_packet();
    pkt.insert(pkt.end(), 8, 0x00);
    auto result = parse_udp_packet(pkt);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload.size(), 4u);
}

TEST(PacketParser, RejectsNotUdp) {
    auto pkt = make_valid_packet();
    pkt[14 + 9] = 6; // TCP
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::NotUdp);
}

TEST(PacketParser, RejectsIhlBelowFive) {
    auto pkt = make_valid_packet();
    pkt[14] = 0x44; // ihl = 4 words = 16 bytes
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::IhlOutOfRange);
}

TEST(PacketParser, RejectsTooShortForUdp) {
    auto pkt = make_valid_packet();
    pkt[14 + 3] = 24; // ip total_length leaves only 4 bytes after the header
    auto result = parse_udp_packet(pkt);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), ParseError::TooShortForUdp);
}

TEST(PacketParser, ParsesIpv4Options) {
    auto pkt = make_valid_packet();
    pkt[14] = 0x46;   // ihl = 6 words = 24 bytes
    pkt[14 + 3] = 36; // total_length = 24 + 12
    pkt.insert(pkt.begin() + 34, 4, 0x00); // 4 option bytes
    auto result = parse_udp_packet(pkt);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->payload.size(), 4u);
    EXPECT_EQ(result->payload[0], 0xDE);
}
