// Stub fingerprint for SM-A736B / A736BXXSCGZF1.
// The tracefs oracle (APP_TRACEFS_SLIDE) provides the KASLR slide on this
// target without ever consulting these fingerprints.  Entries are zeroed so
// the physical P0 oracle fails cleanly if tracefs is unavailable.
// To fill in real values: dump kernel Image, then for each slide S sample
//   Image[P0_ORACLE_PROBE_OFFSET - S + offset] for each offset below.
#ifndef P0_FINGERPRINT_H
#define P0_FINGERPRINT_H

#define P0_FINGERPRINT_WORDS 8

static const uint16_t p0_fingerprint_offsets[P0_FINGERPRINT_WORDS] = {
  0x000, 0x200, 0x400, 0x600, 0x800, 0xa00, 0xc00, 0xe00,
};

struct p0_fingerprint {
  uintptr_t slide;
  uint64_t words[P0_FINGERPRINT_WORDS];
};

static const struct p0_fingerprint p0_fingerprints[] = {
  { 0x000000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x010000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x020000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x030000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x040000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x050000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x060000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x070000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x080000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x090000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0a0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0b0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0c0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0d0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0e0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x0f0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x100000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x110000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x120000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x130000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x140000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x150000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x160000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x170000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x180000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x190000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1a0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1b0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1c0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1d0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1e0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
  { 0x1f0000ULL, { 0, 0, 0, 0, 0, 0, 0, 0 } },
};

#endif
