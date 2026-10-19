#pragma once
#include <cstdint>
#include <cstddef>
#include <span>

#if defined(__x86_64__)
#include <immintrin.h>
#endif

namespace aether {

inline uint32_t checksum_scalar(std::span<const uint8_t> data) {
    uint64_t sum = 0;
    std::size_t i = 0;

    for (; i + 1 < data.size(); i += 2) {
        uint16_t word = static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
        sum += word;
    }
    if (i < data.size()) {
        sum += static_cast<uint16_t>(data[i] << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint32_t>(sum);
}

#if defined(__x86_64__)
// Handles at most 64 KiB (32-bit lane accumulators); use checksum_avx2() for any size.
[[gnu::target("avx2")]]
inline uint32_t checksum_avx2_block(std::span<const uint8_t> data) {
    __m256i acc = _mm256_setzero_si256();
    std::size_t i = 0;

    const __m256i swap_mask = _mm256_set_epi8(
        30,31, 28,29, 26,27, 24,25, 22,23, 20,21, 18,19, 16,17,
        14,15, 12,13, 10,11, 8,9,  6,7,   4,5,   2,3,   0,1
    );

    for (; i + 32 <= data.size(); i += 32) {
        if (i + 128 < data.size()) {
            _mm_prefetch(reinterpret_cast<const char*>(data.data() + i + 128), _MM_HINT_T0);
        }
        __m256i chunk = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(data.data() + i));
        chunk = _mm256_shuffle_epi8(chunk, swap_mask);

        __m128i lo128 = _mm256_castsi256_si128(chunk);
        __m128i hi128 = _mm256_extracti128_si256(chunk, 1);

        __m256i lo32 = _mm256_cvtepu16_epi32(lo128);
        __m256i hi32 = _mm256_cvtepu16_epi32(hi128);

        acc = _mm256_add_epi32(acc, lo32);
        acc = _mm256_add_epi32(acc, hi32);
    }

    alignas(32) uint32_t lanes[8];
    _mm256_store_si256(reinterpret_cast<__m256i*>(lanes), acc);
    uint32_t sum = 0;
    for (int lane = 0; lane < 8; lane++) sum += lanes[lane];

    if (i < data.size()) {
        sum += checksum_scalar(data.subspan(i));
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return sum;
}

// Public AVX2 entry: 64 KiB blocks keep the 32-bit lanes and the horizontal
// sum from overflowing; block totals are accumulated in 64 bits.
inline uint32_t checksum_avx2(std::span<const uint8_t> data) {
    constexpr std::size_t kBlock = 64 * 1024; // even, so 16-bit word alignment holds
    uint64_t total = 0;
    while (data.size() > kBlock) {
        total += checksum_avx2_block(data.first(kBlock));
        data = data.subspan(kBlock);
    }
    total += checksum_avx2_block(data);
    while (total >> 16) {
        total = (total & 0xFFFF) + (total >> 16);
    }
    return static_cast<uint32_t>(total);
}
#endif

inline uint32_t checksum(std::span<const uint8_t> data) {
#if defined(__x86_64__)
    if (__builtin_cpu_supports("avx2")) {
        return checksum_avx2(data);
    }
#endif
    return checksum_scalar(data);
}

// RFC 1071 Internet checksum: one's complement of the folded sum above.
inline uint16_t internet_checksum(std::span<const uint8_t> data) {
    return static_cast<uint16_t>(~checksum(data));
}

} // namespace aether
