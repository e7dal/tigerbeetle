const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const meta = std.meta;
const os = std.os;

const config = @import("../config.zig");
const utils = @import("../utils.zig");
const vsr = @import("../vsr.zig");

const BlockFreeSet = @import("block_free_set.zig").BlockFreeSet;

const log = std.log.scoped(.superblock);

pub const log_level: std.log.Level = .debug;

/// Identifies the type of a sector or block. Protects against misdirected I/O across valid types.
pub const Magic = enum(u8) {
    superblock,
    manifest,
    prepare,
    index,
    filter,
    data,
};

pub const SuperBlockVersion: u8 = 0;

// Fields are aligned to work as an extern or packed struct.
pub const SuperBlockSector = extern struct {
    checksum: u128 = undefined,

    /// Protects against misdirected reads at startup.
    /// For example, if multiple reads are all misdirected to a single copy of the superblock.
    /// Excluded from the checksum calculation to ensure that all copies have the same checksum.
    /// This simplifies writing and comparing multiple copies.
    copy: u8 = 0,

    /// Protects against misdirected I/O for non-superblock sectors that have a valid checksum.
    magic: Magic,

    /// The version of the superblock format in use, reserved for major breaking changes.
    version: u8,

    /// Protects against writing to or reading from the wrong data file.
    replica: u8,
    cluster: u32,

    /// The current size of the data file.
    size: u64,

    /// The maximum size of the data file.
    size_max: u64,

    /// A monotonically increasing counter to locate the latest superblock at startup.
    sequence: u64,

    /// The checksum of the previous superblock to hash chain across sequence numbers.
    parent: u128,

    /// The checksum over the manifest block references in the superblock trailer.
    manifest_checksum: u128,

    /// The checksum over the actual encoded block free set in the superblock trailer.
    block_free_set_checksum: u128,

    /// State stored on stable storage for the Viewstamped Replication consensus protocol.
    vsr_state: VSRState,

    /// Reserved for future minor features (e.g. changing the compression algorithm of the trailer).
    flags: u64 = 0,

    /// A listing of VSR client table messages committed to the state machine.
    /// These are stored in a client table zone containing messages up to message_size_max.
    /// We recover any faulty client table entries as prepare messages and not as block messages.
    client_table: [config.clients_max]ClientTableEntry,

    /// A listing of persistent read snapshots that have been issued to clients.
    /// A snapshot.created timestamp of 0 indicates that the snapshot is null.
    snapshots: [config.lsm_snapshots_max]Snapshot,

    /// The size of the manifest block references stored in the superblock trailer.
    /// The block addresses and checksums in this section of the trailer are laid out as follows:
    /// [manifest_size / (16 + 8)]u128 checksum
    /// [manifest_size / (16 + 8)]u64 address
    manifest_size: u32,

    /// The size of the block free set stored in the superblock trailer.
    block_free_set_size: u32,

    reserved: [2168]u8 = [1]u8{0} ** 2168,

    pub const VSRState = extern struct {
        /// The last operation committed to the state machine. At startup, replay the log hereafter.
        commit_min: u64,

        /// The highest operation up to which we may commit.
        commit_max: u64,

        /// The last view in which the replica's status was normal.
        view_normal: u32,

        /// The view number of the replica.
        view: u32,

        comptime {
            assert(@sizeOf(VSRState) == 24);
        }

        pub fn check(state: VSRState) void {
            assert(state.commit_max >= state.commit_min);
            assert(state.view >= state.view_normal);
        }

        pub fn would_be_updated_by(state: VSRState, new: VSRState) bool {
            state.check();
            new.check();

            assert(new.view >= state.view);
            assert(new.view_normal >= state.view_normal);
            assert(new.commit_min >= state.commit_min);
            assert(new.commit_max >= state.commit_max);

            return !meta.eql(state, new);
        }

        pub fn update(state: *VSRState, new: VSRState) void {
            assert(state.would_be_updated_by(new));
            state.* = new;
        }
    };

    pub const ClientTableEntry = extern struct {
        message_checksum: u128,
        message_offset: u64,

        /// A session number of 0 indicates that the entry is null.
        /// Our VSR session numbers are always greater than 0 since the 0 commit number is reserved.
        session: u64,

        pub fn exists(entry: ClientTableEntry) bool {
            if (entry.session == 0) {
                assert(entry.message_checksum == 0);
                assert(entry.message_offset == 0);

                return false;
            } else {
                return true;
            }
        }

        comptime {
            assert(@sizeOf(ClientTableEntry) == 32);
        }
    };

    pub const Snapshot = extern struct {
        /// A creation timestamp of 0 indicates that the snapshot is null.
        created: u64,

        /// When a read query last used the snapshot.
        queried: u64,

        /// Snapshots may auto-expire after a timeout of inactivity.
        /// A timeout of 0 indicates that the snapshot must be explicitly released by the user.
        timeout: u64,

        pub fn exists(snapshot: Snapshot) bool {
            if (snapshot.created == 0) {
                assert(snapshot.queried == 0);
                assert(snapshot.timeout == 0);

                return false;
            } else {
                return true;
            }
        }

        comptime {
            assert(@sizeOf(Snapshot) == 24);
        }
    };

    comptime {
        assert(@sizeOf(SuperBlockSector) == config.sector_size);
    }

    pub fn calculate_checksum(superblock: *const SuperBlockSector) u128 {
        comptime assert(meta.fieldIndex(SuperBlockSector, "checksum") == 0);
        comptime assert(meta.fieldIndex(SuperBlockSector, "copy") == 1);

        const checksum_size = @sizeOf(@TypeOf(superblock.checksum));
        comptime assert(checksum_size == 16);

        const copy_size = @sizeOf(@TypeOf(superblock.copy));
        comptime assert(copy_size == 1);

        const ignore_size = checksum_size + copy_size;

        var target: [32]u8 = undefined;
        crypto.hash.Blake3.hash(std.mem.asBytes(superblock)[ignore_size..], target[0..], .{});
        return @bitCast(u128, target[0..checksum_size].*);
    }

    pub fn set_checksum(superblock: *SuperBlockSector) void {
        assert(superblock.copy < superblock_copies_max);
        assert(superblock.magic == .superblock);
        assert(superblock.version == SuperBlockVersion);
        assert(superblock.flags == 0);

        for (mem.bytesAsSlice(u64, &superblock.reserved)) |word| assert(word == 0);

        superblock.checksum = superblock.calculate_checksum();
    }

    pub fn valid_checksum(superblock: *const SuperBlockSector) bool {
        return superblock.checksum == superblock.calculate_checksum();
    }
};

comptime {
    assert(config.superblock_copies >= 3);
    assert(config.superblock_copies <= 8);
}

/// The size of the entire superblock storage zone.
pub const superblock_zone_size = superblock_size * superblock_copies_max;

/// A single copy set consists of config.superblock_copies of a superblock.
/// At least two copy sets are required for copy-on-write in order not to impair existing copies.
///
/// However, when writing only the superblock sector for a view change, we do update-in-place,
/// which is necessary as we need to continue to reference the existing superblock trailer to
/// decouple view changes from checkpoints, to not force an untimely checkpoint ahead of schedule.
pub const superblock_copies_max = config.superblock_copies * 2;

/// The size of an individual superblock including trailer.
pub const superblock_size = @sizeOf(SuperBlockSector) + superblock_trailer_size_max;
comptime {
    assert(superblock_size % config.sector_size == 0);
}

/// The maximum possible size of the superblock trailer, following the superblock sector.
const superblock_trailer_size_max = blk: {
    // To calculate the size of the superblock trailer we need to know:
    // 1. the maximum number of manifest blocks that should be able to be referenced, and
    // 2. the maximum possible size of the EWAH-compressed bit set addressable by BlockFreeSet.

    assert(superblock_trailer_manifest_size_max > 0);
    assert(superblock_trailer_manifest_size_max % config.sector_size == 0);

    assert(superblock_trailer_block_free_set_size_max > 0);
    assert(superblock_trailer_block_free_set_size_max % config.sector_size == 0);

    // We order the smaller manifest section ahead of the block free set for better access locality.
    // For example, it's cheaper to skip over 1 MiB when reading from disk than to skip over 32 MiB.
    break :blk superblock_trailer_manifest_size_max + superblock_trailer_block_free_set_size_max;
};

// A manifest block reference of 24 bytes contains a block address and checksum.
// We store these references back to back in the trailer.
// A 4 KiB sector can contain 170.66 of these references.
// A manifest block of 64 KiB in turn can store 511 TableInfos (32 byte keys, plus tree/level meta).
// Therefore 1 MiB of references equates to 256 sectors, 43520 manifest blocks or 22 million tables.
// This allows room for switching from 64 KiB to a smaller block size without limiting table count.
// It's also not material in comparison to the size of the trailer's encoded block free set.
const superblock_trailer_manifest_size_max = 1048576;

const superblock_trailer_block_free_set_size_max = blk: {
    // Local storage consists of four zones: Superblock, WriteAheadLog, ClientTable, Block.
    //
    // We slightly overestimate the number of locally addressable blocks, where this depends on:
    // * the size of the WAL, because this is only runtime known, and
    // * the size of the superblock zone itself, because this introduces a more complex cycle.
    //
    // However, this padding is 20 KiB for a 10 GiB WAL and a few bytes for the superblock zone.
    //
    // This maximum blocks count enables us to calculate the maximum trailer size at comptime, and
    // is not what we will pass to BlockFreeSet at runtime. We will instead pass a reduced count to
    // eventually take the WAL and superblock zones into account at runtime.

    const client_table_size = config.clients_max * config.message_size_max;
    const blocks_count = @divFloor(config.size_max - client_table_size, config.block_size);

    // Further massage this blocks count into a value that is acceptable to BlockFreeSet:
    const blocks_count_floor = BlockFreeSet.blocks_count_floor(blocks_count);
    const encode_size_max = BlockFreeSet.encode_size_max(blocks_count_floor);

    // Round this up to the nearest sector:
    break :blk utils.div_ceil(encode_size_max, config.sector_size) * config.sector_size;
};

pub fn SuperBlock(comptime Storage: type) type {
    return struct {
        const SuperBlockGeneric = @This();

        pub const Context = struct {
            pub const Callee = enum {
                checkpoint,
                view_change,
                open,
            };

            superblock: *SuperBlockGeneric,
            callback: fn (context: *Context) void,
            callee: Callee,
            write: Storage.Write,
            read: Storage.Read,
            copy: u8,
        };

        storage: *Storage,
        storage_offset: u64 = 0,
        storage_length: u64 = superblock_zone_size,

        locked: bool = false,

        /// The superblock that was recovered at startup after a crash or that was last written.
        working: *align(config.sector_size) SuperBlockSector,

        /// The superblock that will replace the current working superblock once written.
        /// This is used when writing the staging superblock, or when changing views before then.
        /// We cannot mutate any working state directly until it is safely on stable storage.
        /// Otherwise, we may accidentally externalize guarantees that are not yet durable.
        writing: *align(config.sector_size) SuperBlockSector,

        /// The superblock that will be checkpointed next.
        /// This may be updated incrementally several times before the next checkpoint.
        /// For example, to track new snapshots as they are registered.
        staging: *align(config.sector_size) SuperBlockSector,

        /// The copies that we read into at startup or when verifying the written superblock.
        reading: []align(config.sector_size) SuperBlockSector,

        quorums: Quorums = Quorums{},

        pub fn init(allocator: mem.Allocator, storage: *Storage) !SuperBlockGeneric {
            const a = try allocator.allocAdvanced(SuperBlockSector, config.sector_size, 1, .exact);
            errdefer allocator.free(a);

            const b = try allocator.allocAdvanced(SuperBlockSector, config.sector_size, 1, .exact);
            errdefer allocator.free(b);

            const c = try allocator.allocAdvanced(SuperBlockSector, config.sector_size, 1, .exact);
            errdefer allocator.free(c);

            // TODO(ifreund) Can we improve this? Is the corresponding free() 100%?
            const reading = try allocator.allocAdvanced(
                [config.superblock_copies * 2]SuperBlockSector,
                config.sector_size,
                1,
                .exact,
            );
            errdefer allocator.free(reading);

            return SuperBlockGeneric{
                .storage = storage,
                .working = &a[0],
                .writing = &b[0],
                .staging = &c[0],
                .reading = &reading[0],
            };
        }

        pub fn deinit(superblock: *SuperBlockGeneric, allocator: mem.Allocator) void {
            assert(!superblock.locked);

            // TODO Set and assert on magic.

            allocator.destroy(superblock.working);
            allocator.destroy(superblock.writing);
            allocator.destroy(superblock.staging);

            allocator.free(superblock.reading);
        }

        // TODO Move these down.
        fn starting_copy_for_sequence(sequence: u64) u8 {
            return config.superblock_copies * @intCast(u8, sequence % 2);
        }

        fn stopping_copy_for_sequence(sequence: u64) u8 {
            return starting_copy_for_sequence(sequence) + config.superblock_copies - 1;
        }

        pub fn checkpoint(
            superblock: *SuperBlockGeneric,
            callback: fn (context: *Context) void,
            context: *Context,
        ) void {
            assert(!superblock.locked);
            superblock.locked = true;

            context.* = .{
                .superblock = superblock,
                .callback = callback,
                .callee = .checkpoint,
                .write = undefined,
                .read = undefined,
                .copy = starting_copy_for_sequence(superblock.staging.sequence),
            };

            superblock.writing.* = superblock.staging.*;
            superblock.writing.set_checksum();

            assert(superblock.writing.sequence == superblock.working.sequence + 1);
            assert(superblock.writing.parent == superblock.working.checksum);

            superblock.staging.sequence = superblock.writing.sequence + 1;
            superblock.staging.parent = superblock.writing.checksum;

            superblock.write_sector(context);
        }

        pub fn view_change(
            superblock: *SuperBlockGeneric,
            callback: fn (context: *Context) void,
            context: *Context,
            vsr_state: SuperBlockSector.VSRState,
        ) void {
            assert(!superblock.locked);
            superblock.locked = true;

            context.* = .{
                .superblock = superblock,
                .callback = callback,
                .callee = .view_change,
                .write = undefined,
                .read = undefined,
                .copy = starting_copy_for_sequence(superblock.working.sequence),
            };

            log.debug(
                "view_change: commit_min={}..{} commit_max={}..{} view_normal={}..{} view={}..{}",
                .{
                    superblock.working.vsr_state.commit_min,
                    vsr_state.commit_min,

                    superblock.working.vsr_state.commit_max,
                    vsr_state.commit_max,

                    superblock.working.vsr_state.view_normal,
                    vsr_state.view_normal,

                    superblock.working.vsr_state.view,
                    vsr_state.view,
                },
            );

            vsr_state.check();

            if (!superblock.working.vsr_state.would_be_updated_by(vsr_state)) {
                log.debug("view_change: no change", .{});

                superblock.locked = false;
                callback(context);
                return;
            }

            superblock.writing.* = superblock.working.*;

            // We cannot bump the sequence number when writing only the superblock sector because
            // this would write the sector to another copy set with different superblock trailers.

            superblock.writing.vsr_state.update(vsr_state);
            superblock.staging.vsr_state.update(vsr_state);

            superblock.writing.set_checksum();

            assert(superblock.staging.sequence == superblock.writing.sequence + 1);
            superblock.staging.parent = superblock.writing.checksum;

            superblock.write_sector(context);
        }

        fn write_sector(superblock: *SuperBlockGeneric, context: *Context) void {
            assert(superblock.locked);

            // We are either updating the working superblock for a view change or checkpointing:
            assert(superblock.writing.sequence == superblock.working.sequence or
                superblock.writing.sequence == superblock.working.sequence + 1);

            // The staging superblock should always be one ahead, with VSR state in sync:
            assert(superblock.staging.sequence == superblock.writing.sequence + 1);
            assert(superblock.staging.parent == superblock.writing.checksum);
            assert(meta.eql(superblock.staging.vsr_state, superblock.writing.vsr_state));

            assert(context.copy < superblock_copies_max);
            assert(context.copy >= starting_copy_for_sequence(superblock.writing.sequence));
            assert(context.copy <= stopping_copy_for_sequence(superblock.writing.sequence));
            superblock.writing.copy = context.copy;

            // Updating the copy number should not affect the checksum, which was previously set:
            assert(superblock.writing.valid_checksum());

            const buffer = mem.asBytes(superblock.writing);
            const offset = superblock_size * context.copy;

            assert(offset >= superblock.storage_offset);
            assert(offset + buffer.len + superblock_trailer_size_max <= superblock.storage_length);

            log.debug("write_sector: checksum={} sequence={} copy={} size={} offset={}", .{
                superblock.writing.checksum,
                superblock.writing.sequence,
                context.copy,
                buffer.len,
                offset,
            });

            superblock.storage.write_sectors(write_sector_callback, &context.write, buffer, offset);
        }

        fn write_sector_callback(write: *Storage.Write) void {
            const context = @fieldParentPtr(Context, "write", write);
            const superblock = context.superblock;

            assert(superblock.locked);

            assert(context.copy < superblock_copies_max);
            assert(context.copy >= starting_copy_for_sequence(superblock.writing.sequence));
            assert(context.copy <= stopping_copy_for_sequence(superblock.writing.sequence));
            assert(context.copy == superblock.writing.copy);

            if (context.copy == stopping_copy_for_sequence(superblock.writing.sequence)) {
                superblock.verify(context.callback, context, context.callee);
            } else {
                context.copy += 1;
                superblock.write_sector(context);
            }
        }

        pub fn open(
            superblock: *SuperBlockGeneric,
            callback: fn (context: *Context) void,
            context: *Context,
        ) void {
            assert(!superblock.locked);
            superblock.locked = true;

            superblock.verify(callback, context, .open);
        }

        fn verify(
            superblock: *SuperBlockGeneric,
            callback: fn (context: *Context) void,
            context: *Context,
            callee: Context.Callee,
        ) void {
            assert(superblock.locked);

            // We do not submit reads in parallel, as while this would shave off 1ms, it would also
            // increase the risk that a single fault applies to more reads due to temporal locality.
            // This would make verification reads more flaky when we do experience a read fault.
            // See "An Analysis of Data Corruption in the Storage Stack".

            context.* = .{
                .superblock = superblock,
                .callback = callback,
                .callee = callee,
                .write = undefined,
                .read = undefined,
                .copy = 0,
            };

            for (superblock.reading) |*copy| copy.* = undefined;
            superblock.read_sector(context);
        }

        fn read_sector(superblock: *SuperBlockGeneric, context: *Context) void {
            assert(superblock.locked);
            assert(context.copy < superblock_copies_max);

            const buffer = mem.asBytes(&superblock.reading[context.copy]);
            const offset = superblock_size * context.copy;

            assert(offset >= superblock.storage_offset);
            assert(offset + buffer.len + superblock_trailer_size_max <= superblock.storage_length);

            log.debug("read_sector: copy={} size={} offset={}", .{
                context.copy,
                buffer.len,
                offset,
            });

            superblock.storage.read_sectors(read_sector_callback, &context.read, buffer, offset);
        }

        fn read_sector_callback(read: *Storage.Read) void {
            const context = @fieldParentPtr(Context, "read", read);
            const superblock = context.superblock;

            assert(superblock.locked);
            assert(context.copy < superblock_copies_max);

            if (context.copy == superblock_copies_max - 1) {
                log.debug("finished reading all copies", .{});

                const threshold = quorum_threshold_for_callee(context.callee);

                if (superblock.quorums.working(superblock.reading, threshold)) |working| {
                    switch (context.callee) {
                        .checkpoint, .view_change => {
                            if (working.checksum != superblock.writing.checksum) {
                                @panic("superblock failed verification after writing");
                            }
                        },
                        .open => {},
                    }

                    superblock.working.* = working.*;

                    log.debug("installed working superblock: checksum={} sequence={}", .{
                        working.checksum,
                        working.sequence,
                    });
                }

                superblock.locked = false;
                context.callback(context);
            } else {
                context.copy += 1;
                superblock.read_sector(context);
            }
        }

        // TODO Fix working copy overwrite quorum for view changes.
        // Bump the sequence number by two as an easy fix.

        /// We use flexible quorums for even quorums with write quorum > read quorum, for example:
        /// * When writing, we must verify that at least 3/4 copies were written.
        /// * At startup, we must verify that at least 2/4 copies were read.
        ///
        /// This ensures that our read and write quorums will intersect.
        /// Using flexible quorums in this way increases resiliency of the superblock.
        fn quorum_threshold_for_callee(callee: Context.Callee) u8 {
            // Working these threshold out by formula is easy to get wrong, so enumerate them:
            // The rule is that the write quorum plus the read quorum must be exactly copies + 1.

            return switch (callee) {
                .checkpoint, .view_change => switch (config.superblock_copies) {
                    4 => 3,
                    6 => 4,
                    8 => 5,
                    else => unreachable,
                },
                // The open quorum must allow for at least two copy faults, because our view change
                // updates an existing set of copies in place, temporarily impairing one copy.
                .open => switch (config.superblock_copies) {
                    4 => 2,
                    6 => 3,
                    8 => 4,
                    else => unreachable,
                },
            };
        }
    };
}

const Quorums = struct {
    const Quorum = struct {
        checksum: u128,
        sequence: u64,
        parent: u128,
        sector: *const SuperBlockSector,
        count: QuorumCount = QuorumCount.initEmpty(),
        valid: bool = false,
    };

    const QuorumCount = std.StaticBitSet(superblock_copies_max);

    array: [superblock_copies_max]Quorum = undefined,
    count: u8 = 0,

    pub fn working(
        quorums: *Quorums,
        copies: []SuperBlockSector,
        threshold: u8,
    ) ?*const SuperBlockSector {
        assert(copies.len == superblock_copies_max);
        assert(threshold >= 2 and threshold <= 5);

        quorums.array = undefined;
        quorums.count = 0;

        for (copies) |copy, index| quorums.count_copy(&copy, index, threshold);

        std.sort.sort(Quorum, quorums.slice(), {}, sort_a_before_b);

        // TODO Verify quorum order.

        for (quorums.slice()) |quorum| {
            if (quorum.count.count() == config.superblock_copies) {
                log.debug("quorum: checksum={} sequence={} count={} valid={}", .{
                    quorum.checksum,
                    quorum.sequence,
                    quorum.count.count(),
                    quorum.valid,
                });
            } else {
                log.err("quorum: checksum={} sequence={} count={} valid={}", .{
                    quorum.checksum,
                    quorum.sequence,
                    quorum.count.count(),
                    quorum.valid,
                });
            }
        }

        // TODO Verify parent.

        for (quorums.slice()) |quorum| {
            if (quorum.valid) return quorum.sector;
        }
        return null;
    }

    fn count_copy(
        quorums: *Quorums,
        copy: *const SuperBlockSector,
        index: usize,
        threshold: u8,
    ) void {
        assert(index < superblock_copies_max);
        assert(threshold >= 2 and threshold <= 5);

        if (!copy.valid_checksum()) {
            log.debug("copy: {}/{}: invalid checksum", .{ index, superblock_copies_max });
            return;
        }

        if (copy.magic != .superblock) {
            log.debug("copy: {}/{}: not a superblock", .{ index, superblock_copies_max });
            return;
        }

        if (copy.copy == index) {
            log.debug("copy: {}/{}: checksum={} sequence={}", .{
                index,
                superblock_copies_max,
                copy.checksum,
                copy.sequence,
            });
        } else {
            // If our read was misdirected, we definitely still want to count the copy.
            // We must just be careful to count it idempotently.
            log.err(
                "copy: {}/{}: checksum={} sequence={} misdirected from copy={}",
                .{
                    index,
                    superblock_copies_max,
                    copy.checksum,
                    copy.sequence,
                    copy.copy,
                },
            );
        }

        var quorum = quorums.find_or_insert_quorum_for_copy(copy);

        // TODO Replace this with superblock.equals().
        assert(quorum.checksum == copy.checksum);
        assert(quorum.sequence == copy.sequence);
        assert(quorum.parent == copy.parent);
        assert(meta.eql(quorum.sector.vsr_state, copy.vsr_state));

        quorum.count.set(copy.copy);
        assert(quorum.count.isSet(copy.copy));

        // In the worst case, all copies may contain divergent forks of the same sequence.
        // However, this should not happen for the same checksum.
        assert(quorum.count.count() <= config.superblock_copies);

        quorum.valid = quorum.count.count() >= threshold;
    }

    fn find_or_insert_quorum_for_copy(quorums: *Quorums, copy: *const SuperBlockSector) *Quorum {
        for (quorums.array[0..quorums.count]) |*quorum| {
            if (copy.checksum == quorum.checksum) return quorum;
        } else {
            quorums.array[quorums.count] = Quorum{
                .checksum = copy.checksum,
                .sequence = copy.sequence,
                .parent = copy.parent,
                .sector = copy,
            };
            quorums.count += 1;

            return &quorums.array[quorums.count - 1];
        }
    }

    fn slice(quorums: *Quorums) []Quorum {
        return quorums.array[0..quorums.count];
    }

    fn sort_a_before_b(_: void, a: Quorum, b: Quorum) bool {
        assert(a.checksum != b.checksum);

        if (a.valid and !b.valid) return true;
        if (b.valid and !a.valid) return false;

        if (a.sequence > b.sequence) return true;
        if (b.sequence > a.sequence) return false;

        if (a.count.count() > b.count.count()) return true;
        if (b.count.count() > a.count.count()) return false;

        return a.checksum > b.checksum;
    }
};

test "SuperBlockSector" {
    const expect = std.testing.expect;

    var a = std.mem.zeroInit(SuperBlockSector, .{});
    a.set_checksum();

    assert(a.copy == 0);
    try expect(a.valid_checksum());

    a.copy += 1;
    try expect(a.valid_checksum());

    a.replica += 1;
    try expect(!a.valid_checksum());
}

pub fn main() !void {
    const testing = std.testing;
    const allocator = testing.allocator;

    const IO = @import("../io.zig").IO;
    const Storage = @import("../storage.zig").Storage;

    const dir_path = ".";
    const dir_fd = os.openZ(dir_path, os.O.CLOEXEC | os.O.RDONLY, 0) catch |err| {
        std.debug.print("failed to open directory '{s}': {}", .{ dir_path, err });
        return;
    };

    const size = config.journal_size_max * 4;

    const storage_fd = try Storage.open(
        dir_fd,
        "lsm",
        size,
        false, // Set this to true the first time to create the data file.
    );

    var io = try IO.init(128, 0);
    defer io.deinit();

    const cluster = 32;

    var storage = try Storage.init(allocator, &io, cluster, size, storage_fd);
    defer storage.deinit(allocator);

    const TestSuperBlock = SuperBlock(Storage);

    var superblock = try TestSuperBlock.init(allocator, &storage);
    defer superblock.deinit(allocator);

    superblock.working.* = .{
        .copy = 0,
        .magic = .superblock,
        .version = SuperBlockVersion,
        .sequence = 35,
        .replica = 2,
        .cluster = cluster,
        .size = size,
        .size_max = size,
        .parent = 0,
        .manifest_checksum = 0,
        .block_free_set_checksum = 0,
        .vsr_state = .{
            .commit_min = 0,
            .commit_max = 0,
            .view_normal = 0,
            .view = 0,
        },
        .client_table = undefined,
        .snapshots = undefined,
        .manifest_size = 0,
        .block_free_set_size = 0,
    };
    superblock.working.set_checksum();

    superblock.writing.* = mem.zeroInit(SuperBlockSector, .{});

    superblock.staging.* = superblock.working.*;
    superblock.staging.sequence = superblock.working.sequence + 1;
    superblock.staging.parent = superblock.working.parent;

    const manifest_block_reference_size = @sizeOf(u64) + @sizeOf(u128);

    const blocks_per_sector = @divFloor(config.sector_size, manifest_block_reference_size);
    _ = blocks_per_sector;

    // We allow variable size TableInfo structures according to Key.
    // This is a conservative worst-case assuming a 32-byte Key.
    const table_info_size = 48 + 32 * 2;

    const tables_per_block = @divFloor(config.block_size - @sizeOf(vsr.Header), table_info_size);
    _ = tables_per_block;

    const remote_size_max = 128 * 1024 * 1024 * 1024 * 1024;
    const local_and_remote_size_max = config.size_max + remote_size_max;

    const table_count_max = @divFloor(local_and_remote_size_max, config.lsm_table_size_max);

    std.debug.print("\ntable_count_max={}\n", .{table_count_max});

    std.debug.print("@sizeOf(SuperBlockSector)={}\n", .{@sizeOf(SuperBlockSector)});

    std.debug.print("trailer_size_max={}\ntrailer_manifest_size_max={}\ntrailer_block_free_set_size_max={}\n", .{
        superblock_trailer_size_max,
        superblock_trailer_manifest_size_max,
        superblock_trailer_block_free_set_size_max,
    });

    const Time = @import("../time.zig").Time;

    var time = Time{};
    var m0 = time.monotonic();

    var context: TestSuperBlock.Context = undefined;
    superblock.view_change(
        struct {
            fn callback(ctx: *TestSuperBlock.Context) void {
                _ = ctx;

                std.debug.print("done!\n", .{});
            }
        }.callback,
        &context,
        .{
            .commit_min = 0,
            .commit_max = 3,
            .view = 77,
            .view_normal = 50,
        },
    );

    while (superblock.locked) try io.run_for_ns(100);

    const ns = time.monotonic() - m0;
    std.debug.print("ns={}\n", .{ns});

    std.debug.print("superblock_zone_size={}\n", .{superblock_zone_size});
}
