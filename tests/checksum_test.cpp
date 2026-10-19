#include "simd/checksum.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <random>

using namespace aether;

TEST(Checksum, EmptyInput) {
    std::vector<uint8_t> data;
    EXPECT_EQ(checksum_scalar(data), 0u);
}

TEST(Checksum, SingleByte) {
    std::vector<uint8_t> data = {0xAB};
    uint32_t result = checksum_scalar(data);
    EXPECT_EQ(result, 0xAB00u);
}

TEST(Checksum, KnownValue) {
    std::vector<uint8_t> data = {0x00, 0x01, 0x00, 0x02, 0x00, 0x03};
    EXPECT_EQ(checksum_scalar(data), 0x0006u);
}

TEST(Checksum, ScalarAndDispatchAgreeOnVariousSizes) {
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    for (std::size_t size : {0, 1, 2, 31, 32, 33, 63, 64, 65, 1500, 9000}) {
        std::vector<uint8_t> data(size);
        for (auto& b : data) b = static_cast<uint8_t>(byte_dist(rng));

        uint32_t scalar_result = checksum_scalar(data);
        uint32_t dispatch_result = checksum(data);

        EXPECT_EQ(scalar_result, dispatch_result)
            << "mismatch at size " << size;
    }
}

#if defined(__x86_64__)
TEST(Checksum, Avx2MatchesScalarDirectly) {
    if (!__builtin_cpu_supports("avx2")) {
        GTEST_SKIP() << "CPU does not support AVX2";
    }

    std::mt19937 rng(7);
    std::uniform_int_distribution<int> byte_dist(0, 255);

    for (std::size_t size : {32, 64, 96, 1500, 9000}) {
        std::vector<uint8_t> data(size);
        for (auto& b : data) b = static_cast<uint8_t>(byte_dist(rng));

        EXPECT_EQ(checksum_scalar(data), checksum_avx2(data))
            << "mismatch at size " << size;
    }
}
#endif

// Independent reference: 64-bit accumulator, fold at the end.
static uint32_t reference_sum(const std::vector<uint8_t>& d) {
    uint64_t s = 0;
    for (std::size_t i = 0; i + 1 < d.size(); i += 2) s += static_cast<uint32_t>((d[i] << 8) | d[i + 1]);
    if (d.size() & 1) s += static_cast<uint32_t>(d.back() << 8);
    while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
    return static_cast<uint32_t>(s);
}

TEST(Checksum, Rfc1071Example) {
    std::vector<uint8_t> d = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    EXPECT_EQ(checksum_scalar(d), 0xddf2u);
    EXPECT_EQ(internet_checksum(d), 0x220du);
}

TEST(Checksum, LargeInputsMatchReference) {
    std::mt19937 rng(99);
    for (std::size_t size : {65535, 65536, 65537, 131072, 140000, 1200000, 5000001}) {
        std::vector<uint8_t> ones(size, 0xFF); // worst case for carries
        EXPECT_EQ(checksum_scalar(ones), reference_sum(ones)) << "ones, size " << size;
        EXPECT_EQ(checksum(ones), reference_sum(ones)) << "ones dispatch, size " << size;

        std::vector<uint8_t> rnd(size);
        for (auto& b : rnd) b = static_cast<uint8_t>(rng());
        EXPECT_EQ(checksum_scalar(rnd), reference_sum(rnd)) << "random, size " << size;
        EXPECT_EQ(checksum(rnd), reference_sum(rnd)) << "random dispatch, size " << size;
    }
}

#if defined(__x86_64__)
TEST(Checksum, Avx2LargeInputsMatchReference) {
    if (!__builtin_cpu_supports("avx2")) GTEST_SKIP() << "CPU does not support AVX2";
    for (std::size_t size : {65536, 65537, 140000, 1200000, 5000001}) {
        std::vector<uint8_t> ones(size, 0xFF);
        EXPECT_EQ(checksum_avx2(ones), reference_sum(ones)) << "size " << size;
    }
}
#endif

TEST(Checksum, UnalignedStartMatchesReference) {
    std::mt19937 rng(5);
    std::vector<uint8_t> buf(4096 + 8);
    for (auto& b : buf) b = static_cast<uint8_t>(rng());
    for (std::size_t off = 0; off < 8; off++) {
        std::vector<uint8_t> view(buf.begin() + static_cast<std::ptrdiff_t>(off), buf.end());
        EXPECT_EQ(checksum(view), reference_sum(view)) << "offset " << off;
    }
}

TEST(Checksum, AppendingChecksumVerifiesToZero) {
    std::mt19937 rng(11);
    for (std::size_t size : {20, 64, 1500, 9000}) {
        std::vector<uint8_t> d(size);
        for (auto& b : d) b = static_cast<uint8_t>(rng());
        uint16_t c = internet_checksum(d);
        d.push_back(static_cast<uint8_t>(c >> 8));
        d.push_back(static_cast<uint8_t>(c & 0xFF));
        EXPECT_EQ(internet_checksum(d), 0u) << "size " << size;
    }
}
