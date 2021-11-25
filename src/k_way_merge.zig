const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

pub fn KWayMergeIterator(
    comptime Context: type,
    comptime Key: type,
    comptime Value: type,
    comptime keys_ordered: fn (Key, Key) bool,
    comptime k_max: u32,
    comptime stream_peek: fn (context: *Context, stream: u32) ?Key,
    comptime stream_pop: fn (context: *Context, stream: u32) Value,
    comptime stream_done: fn (context: *Context, stream: u32) bool,
) type {
    return struct {
        const Self = @This();

        context: *Context,
        keys: [k_max]Key,
        streams: [k_max]u32,
        k: u32,
        valid: bool,

        pub fn init(context: *Context, streams: []const u32) Self {
            var it: Self = .{
                .context = context,
                .keys = undefined,
                .streams = undefined,
                .k = @intCast(u32, streams.len),
                .valid = true,
            };

            for (streams) |stream, i| {
                it.keys[i] = stream_peek(context, stream).?;
                it.streams[i] = stream;
                it.up_heap(@intCast(u32, i));
            }

            return it;
        }

        pub fn pop(it: *Self) ?Value {
            if (it.k == 0 or !it.valid) return null;

            const root = it.streams[0];
            // We know that each input iterator is sorted, so we don't need to compare the next
            // key on that iterator with the current min, we know it is greater.
            const value = stream_pop(it.context, root);

            if (stream_peek(it.context, root)) |key| {
                it.keys[0] = key;
                it.down_heap();
            } else if (stream_done(it.context, root)) {
                it.swap(0, it.k - 1);
                it.k -= 1;
                it.down_heap();
            } else {
                it.valid = false;
            }

            return value;
        }

        fn up_heap(it: *Self, start: u32) void {
            var i = start;
            while (parent(i)) |p| : (i = p) {
                if (it.ordered(p, i)) break;
                it.swap(p, i);
            }
        }

        // Start at the root node.
        // Compare the current node with its children, if the order is correct stop.
        // If the order is incorrect, swap the current node with the smaller child.
        fn down_heap(it: *Self) void {
            if (it.k == 0) return;
            var i: u32 = 0;
            // A maximum of height + 1 interations are required. After height iterations we are
            // guaranteed to be finished or at a leaf node, in which case one more iteration
            // is required to see that the current node has no children and return.
            var safety_count: u32 = 0;
            const binary_tree_height = math.log2_int(u32, it.k) + 1;
            while (safety_count < binary_tree_height + 1) : (safety_count += 1) {
                const left = left_child(i, it.k);
                const right = right_child(i, it.k);

                if (it.ordered(i, left)) {
                    if (it.ordered(i, right)) {
                        break;
                    } else {
                        it.swap(i, right.?);
                        i = right.?;
                    }
                } else if (it.ordered(i, right)) {
                    it.swap(i, left.?);
                    i = left.?;
                } else if (it.ordered(left.?, right.?)) {
                    it.swap(i, left.?);
                    i = left.?;
                } else {
                    it.swap(i, right.?);
                    i = right.?;
                }
            }
            assert(safety_count < binary_tree_height);
        }

        fn parent(node: u32) ?u32 {
            if (node == 0) return null;
            return (node - 1) / 2;
        }

        fn left_child(node: u32, k: u32) ?u32 {
            const child = 2 * node + 1;
            return if (child < k) child else null;
        }

        fn right_child(node: u32, k: u32) ?u32 {
            const child = 2 * node + 2;
            return if (child < k) child else null;
        }

        fn swap(it: *Self, a: u32, b: u32) void {
            mem.swap(Key, &it.keys[a], &it.keys[b]);
            mem.swap(u32, &it.streams[a], &it.streams[b]);
        }

        inline fn ordered(it: Self, a: u32, b: ?u32) bool {
            return b == null or keys_ordered(it.keys[a], it.keys[b.?]);
        }
    };
}

fn TestContext(comptime k_max: u32) type {
    const testing = std.testing;
    return struct {
        const Self = @This();

        streams: [k_max][]const u32,

        fn keys_ordered(a: u32, b: u32) bool {
            return a < b;
        }

        fn stream_peek(context: *Self, index: u32) ?u32 {
            const stream = context.streams[index];
            if (stream.len == 0) return null;
            return stream[0];
        }

        fn stream_pop(context: *Self, index: u32) u32 {
            const stream = context.streams[index];
            context.streams[index] = stream[1..];
            return stream[0];
        }

        fn stream_done(context: *Self, index: u32) bool {
            const stream = context.streams[index];
            return stream.len == 0;
        }

        fn merge(streams: [k_max][]const u32, expect: []const u32) !void {
            const KWay = KWayMergeIterator(
                Self,
                u32,
                u32,
                keys_ordered,
                k_max,
                stream_peek,
                stream_pop,
                stream_done,
            );
            var actual = std.ArrayList(u32).init(testing.allocator);
            defer actual.deinit();

            var context: Self = .{ .streams = streams };
            var stream_indexes: [k_max]u32 = undefined;
            for (stream_indexes) |*index, i| index.* = @intCast(u32, i);
            var kway = KWay.init(&context, &stream_indexes);

            while (kway.pop()) |value| {
                try actual.append(value);
            }

            try testing.expectEqualSlices(u32, expect, actual.items);
        }
    };
}

test "KWayMergeIterator" {
    std.debug.print("\n", .{});
    try TestContext(3).merge(
        [_][]const u32{
            &[_]u32{ 0, 3, 4, 8 },
            &[_]u32{ 1, 2, 11 },
            &[_]u32{ 2, 12, 13, 15 },
        },
        &[_]u32{ 0, 1, 2, 2, 3, 4, 8, 11, 12, 13, 15 },
    );
}
