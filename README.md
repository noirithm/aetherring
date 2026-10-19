# AetherRing

A lock-free packet-processing toolkit in C++23: an SPSC ring buffer, a hugepage arena, io_uring and AF_XDP receive paths, an AVX2 checksum, and a bounds-checked packet parser with a fuzz harness.

Built as a hands-on exploration of atomics and memory ordering, cache behaviour, Linux networking, SIMD, and defensive parsing. Each component is header-only and independent; there is no end-to-end binary yet (see [Status](#status)).

## Components

| Directory          | What it is                                                                                                                                                                                                         |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ring/`            | SPSC ring buffer with cache-line-separated head/tail indices and acquire/release ordering, plus `SpinBackoff` (pause → yield → doubling sleep).                                                                 |
| `arena/`           | Hugepage-backed memory arena with per-core freelists and thread pinning.                                                                                                                                         |
| `net/`             | **io_uring:** multishot UDP receive with a provided buffer ring (the kernel copies into your buffers), plus `SEND_ZC` zero-copy send. **AF_XDP:** UMEM-backed socket with fill/completion/RX rings (no TX path) and an eBPF loader, bound in copy mode with generic (SKB) XDP, so it is not zero-copy.   |
| `ebpf/`            | XDP program that redirects packets to an AF_XDP socket via an `XSKMAP`.                                                                                                                                          |
| `simd/`            | Internet-style 16-bit ones'-complement checksum: AVX2 and scalar versions; `checksum()` dispatches at runtime and `internet_checksum()` returns the RFC 1071 complement. The build uses `-march=x86-64-v3`, so the binary itself requires AVX2.                                                                                                  |
| `proto/`           | Ethernet / IPv4 / UDP parser returning `std::expected`, with a bounds check before every read. Rejects non-IPv4, IP fragments and inconsistent IP/UDP lengths; does not verify checksums or handle VLAN/IPv6.                                                                                                                  |
| `fuzz/`            | libFuzzer harness and seed corpus for the parser.                                                                                                                                                                |
| `tests/`, `bench/` | GoogleTest suites and Google Benchmark suites.                                                                                                                                                                   |

## Requirements

- Linux, x86-64 with AVX2 (the build uses `-march=x86-64-v3`)
- A C++23 compiler (GCC 13+ or Clang 17+) and CMake 3.28+
- `liburing` 2.8 or newer, found through `pkg-config` (required; there is no bundled fallback)
- GoogleTest and Google Benchmark are downloaded automatically by CMake on first configure (network needed)
- Only for `ebpf/` and the AF_XDP loader, which CMake does not build: `clang`, `libbpf`, and kernel headers

## Build and test

    cmake -S . -B build
    cmake --build build -j"$(nproc)"
    ctest --test-dir build --output-on-failure

Add `-DAETHER_TSAN=ON` to the configure step to build with ThreadSanitizer.

The io_uring test needs a kernel with io_uring enabled. AF_XDP has no automated test yet, since it needs a suitable NIC, driver, and privileges.

## Benchmarks

    ./build/bench/ring_bench        # SPSC throughput and ping-pong latency
    ./build/bench/checksum_bench    # scalar vs AVX2, 64 B to 9000 B

Both accept the standard Google Benchmark flags, for example `--benchmark_format=json`. Absolute numbers depend heavily on the CPU, so compare scalar against AVX2 on the same machine rather than across machines. See `docs/PERFORMANCE.md` for tuning notes.

| Packet size | Scalar    | AVX2       | Speedup |
| ----------- | --------- | ---------- | ------- |
| 64 B        | 8.64 GB/s | 13.80 GB/s | 1.6x    |
| 512 B       | 9.73 GB/s | 25.60 GB/s | 2.6x    |
| 1500 B      | 9.63 GB/s | 22.58 GB/s | 2.3x    |
| 9000 B      | 9.68 GB/s | 25.66 GB/s | 2.7x    |

Checksum throughput on a 22-thread CPU at 4.5 GHz, clang-19, Release build. Buffers stay in cache, so these are best-case figures. The scalar baseline is a plain 16-bit-per-step loop, not an optimized 64-bit one, so the speedup is relative to that simple baseline.

## Fuzzing

The packet parser is fuzzed with libFuzzer and AddressSanitizer + UBSan. Build it separately with Clang:

    clang++ -std=c++23 -O1 -g -fsanitize=fuzzer,address,undefined -I. \
        -o packet_fuzz fuzz/packet_fuzz.cpp
    ./packet_fuzz fuzz/corpus -max_total_time=60

A healthy run shows `cov:` growing well past 1 within seconds. The harness also checks that any successfully parsed payload lies inside the input buffer. See `docs/FUZZING.md`.

## Design notes

- **Ring capacity:** `SpscRing<T, N>` keeps one slot empty to tell full from empty, so it holds `N - 1` items. Items are copied in and out by value.
- **Memory ordering:** each side reads its own index with `relaxed` and the other side's with `acquire`, and publishes its own with `release`. `head_` and `tail_` sit on separate cache lines to avoid false sharing.
- **Backoff:** `SpinBackoff` spins with a hardware pause first, then yields, then sleeps with doubling delays (capped at about 1.3 ms), so an idle consumer doesn't hold a core.

## Status

Tested: ring, arena, backoff, checksum, parser, and a single-packet io_uring round trip. The AF_XDP path and eBPF loader have no automated test and are not built by CMake.

Known gaps:

- Components are not yet wired into a single end-to-end pipeline or example program.
- AF_XDP receive and the eBPF loader have no automated test.
- `SpscRing` reads the other side's index on every operation; cached indices would cut cache-line traffic, and free-running indices would let it use all N slots instead of N - 1. (`%` by a constant capacity already compiles to a mask for powers of two.)
- x86-64 / Linux only.

Known issues:

- The io_uring receiver does not re-arm the multishot after an error and does not free its buffer ring.
- Zero-copy send is synchronous (one send in flight), so it is slower than a plain send for small packets.
- The AF_XDP receiver leaks its ring mappings, and the eBPF program redirects all traffic on the queue with no filter.
- The hugepage arena does not round sizes to the hugepage size, and the per-core freelists have no cross-core free path.