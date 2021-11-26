extern fn @"llvm.prefetch.p0i8"(addr: [*]u8, rw: u32, locality: u32, cache_type: u32) void;

const RW = enum {
    read = 0,
    write = 1,
};

const Locality = enum {
    none = 0,
    low = 1,
    moderate = 2,
    high = 3,
};

const CacheType = enum {
    instruction = 0,
    data = 1,
};

pub fn prefetch(
    addr: usize,
    comptime rw: RW,
    comptime locality: Locality,
    comptime cache_type: CacheType,
) void {
    @"llvm.prefetch.p0i8"(
        @intToPtr([*]u8, addr),
        @enumToInt(rw),
        @enumToInt(locality),
        @enumToInt(cache_type),
    );
}
