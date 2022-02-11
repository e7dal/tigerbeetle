const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

pub fn bloom_filter(
    /// Total size in bytes of the filter
    comptime size: u32,
    comptime bits_per_key: u32,
) type {
    assert(size > 0);
    // We treat the raw bytes as 64 bit words for performance..
    assert(size % @sizeOf(u64) == 0);

    const total_bits = size * 8;

    return struct {
        // TODO is u64 the right type here?
        pub const Hashes = [bits_per_key]u64;

        pub fn hash(key: []const u8) Hashes {
            // TODO
        }

        pub fn add(key: []const u8, filter: *align(@alignOf(u64)) [size]u8) void {
            const hashes = hash(key);
            const words = mem.bytesAsSlice(u64, filter);

            for (hashes) |h| {
                const bit_index = h % total_bits;
                const word_index = bit_index / @bitSizeOf(u64);
                const bit = @intCast(math.Log2Int(u64), bit_index % @bitSizeOf(u64));

                words[word_index] |= 1 << bit;
            }
        }

        pub fn may_contain(hashes: Hashes, filter: *align(@alignOf(u64)) const [size]u8) bool {
            const words = mem.bytesAsSlice(u64, filter);

            for (hashes) |h| {
                const bit_index = h % total_bits;
                const word_index = bit_index / @bitSizeOf(u64);
                const bit = @intCast(math.Log2Int(u64), bit_index % @bitSizeOf(u64));

                if (words[word_index] & (1 << bit) == 0) {
                    return false;
                }
            }

            return true;
        }
    };
}
