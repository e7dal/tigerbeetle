const std = @import("std");
const mem = std.mem;
const meta = std.meta;

fn bucket_index(hash: u32, num_buckets: u32) u32 {
    return @intCast(u32, (@as(u64, hash) * num_buckets) >> 32);
}

fn make_mask(hash: u32) meta.Vector(8, u32) {
    const odd_integers: meta.Vector(8, u32) = [8]u32{
        0x47b6137b,
        0x44974d91,
        0x8824ad5b,
        0xa2b7289d,
        0x705495c7,
        0x2df1424b,
        0x9efc4947,
        0x5c6bfb31,
    };

    // Multiply-shift hashing. This produces 8 values in the range 0 to 31 (2^5 - 1).
    const target_bits = (odd_integers * @splat(8, hash)) >> @splat(8, @as(u5, 32 - 5));

    return @splat(8, @as(u32, 1)) << @intCast(meta.Vector(8, u5), target_bits);
}

export fn add_hash(hash: u64, num_buckets: u32, filter: [*]u8) void {
    const mask = make_mask(@truncate(u32, hash));

    const index = bucket_index(@intCast(u32, hash >> 32), num_buckets);
    const bucket_ptr = mem.bytesAsValue([8]u32, filter[index * 32 .. index * 32 + 32][0..32]);

    const old: meta.Vector(8, u32) = bucket_ptr.*;
    bucket_ptr.* = old | mask;
}

export fn find_hash(hash: u64, num_buckets: u32, filter: [*]u8) bool {
    const mask = make_mask(@truncate(u32, hash));

    const index = bucket_index(@intCast(u32, hash >> 32), num_buckets);
    const bucket: meta.Vector(8, u32) = mem.bytesToValue([8]u32, filter[index * 32 .. index * 32 + 32][0..32]);

    return @reduce(.Or, ~bucket & mask) == 0;
}
