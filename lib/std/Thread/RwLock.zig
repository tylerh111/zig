//! A lock that supports one writer or many readers.
//! This API is for kernel threads, not evented I/O.
//! This API requires being initialized at runtime, and initialization
//! can fail. Once initialized, the core operations cannot fail.

impl: Impl = .{},

const RwLock = @This();
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;

pub const Impl = if (builtin.single_threaded)
    SingleThreadedRwLock
else if (std.Thread.use_pthreads)
    PthreadRwLock
else
    DefaultRwLock;

/// Attempts to obtain exclusive lock ownership.
/// Returns `true` if the lock is obtained, `false` otherwise.
pub fn try_lock(rwl: *RwLock) bool {
    return rwl.impl.try_lock();
}

/// Blocks until exclusive lock ownership is acquired.
pub fn lock(rwl: *RwLock) void {
    return rwl.impl.lock();
}

/// Releases a held exclusive lock.
/// Asserts the lock is held exclusively.
pub fn unlock(rwl: *RwLock) void {
    return rwl.impl.unlock();
}

/// Attempts to obtain shared lock ownership.
/// Returns `true` if the lock is obtained, `false` otherwise.
pub fn try_lock_shared(rwl: *RwLock) bool {
    return rwl.impl.try_lock_shared();
}

/// Obtains shared lock ownership.
/// Blocks if another thread has exclusive ownership.
/// May block if another thread is attempting to get exclusive ownership.
pub fn lock_shared(rwl: *RwLock) void {
    return rwl.impl.lock_shared();
}

/// Releases a held shared lock.
pub fn unlock_shared(rwl: *RwLock) void {
    return rwl.impl.unlock_shared();
}

/// Single-threaded applications use this for deadlock checks in
/// debug mode, and no-ops in release modes.
pub const SingleThreadedRwLock = struct {
    state: enum { unlocked, locked_exclusive, locked_shared } = .unlocked,
    shared_count: usize = 0,

    /// Attempts to obtain exclusive lock ownership.
    /// Returns `true` if the lock is obtained, `false` otherwise.
    pub fn try_lock(rwl: *SingleThreadedRwLock) bool {
        switch (rwl.state) {
            .unlocked => {
                assert(rwl.shared_count == 0);
                rwl.state = .locked_exclusive;
                return true;
            },
            .locked_exclusive, .locked_shared => return false,
        }
    }

    /// Blocks until exclusive lock ownership is acquired.
    pub fn lock(rwl: *SingleThreadedRwLock) void {
        assert(rwl.state == .unlocked); // deadlock detected
        assert(rwl.shared_count == 0); // corrupted state detected
        rwl.state = .locked_exclusive;
    }

    /// Releases a held exclusive lock.
    /// Asserts the lock is held exclusively.
    pub fn unlock(rwl: *SingleThreadedRwLock) void {
        assert(rwl.state == .locked_exclusive);
        assert(rwl.shared_count == 0); // corrupted state detected
        rwl.state = .unlocked;
    }

    /// Attempts to obtain shared lock ownership.
    /// Returns `true` if the lock is obtained, `false` otherwise.
    pub fn try_lock_shared(rwl: *SingleThreadedRwLock) bool {
        switch (rwl.state) {
            .unlocked => {
                rwl.state = .locked_shared;
                assert(rwl.shared_count == 0);
                rwl.shared_count = 1;
                return true;
            },
            .locked_shared => {
                rwl.shared_count += 1;
                return true;
            },
            .locked_exclusive => return false,
        }
    }

    /// Blocks until shared lock ownership is acquired.
    pub fn lock_shared(rwl: *SingleThreadedRwLock) void {
        switch (rwl.state) {
            .unlocked => {
                rwl.state = .locked_shared;
                assert(rwl.shared_count == 0);
                rwl.shared_count = 1;
            },
            .locked_shared => {
                rwl.shared_count += 1;
            },
            .locked_exclusive => unreachable, // deadlock detected
        }
    }

    /// Releases a held shared lock.
    pub fn unlock_shared(rwl: *SingleThreadedRwLock) void {
        switch (rwl.state) {
            .unlocked => unreachable, // too many calls to `unlock_shared`
            .locked_exclusive => unreachable, // exclusively held lock
            .locked_shared => {
                rwl.shared_count -= 1;
                if (rwl.shared_count == 0) {
                    rwl.state = .unlocked;
                }
            },
        }
    }
};

pub const PthreadRwLock = struct {
    rwlock: std.c.pthread_rwlock_t = .{},

    pub fn try_lock(rwl: *PthreadRwLock) bool {
        return std.c.pthread_rwlock_trywrlock(&rwl.rwlock) == .SUCCESS;
    }

    pub fn lock(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_wrlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }

    pub fn unlock(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_unlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }

    pub fn try_lock_shared(rwl: *PthreadRwLock) bool {
        return std.c.pthread_rwlock_tryrdlock(&rwl.rwlock) == .SUCCESS;
    }

    pub fn lock_shared(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_rdlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }

    pub fn unlock_shared(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_unlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }
};

pub const DefaultRwLock = struct {
    state: usize = 0,
    mutex: std.Thread.Mutex = .{},
    semaphore: std.Thread.Semaphore = .{},

    const IS_WRITING: usize = 1;
    const WRITER: usize = 1 << 1;
    const READER: usize = 1 << (1 + @bitSizeOf(Count));
    const WRITER_MASK: usize = std.math.max_int(Count) << @ctz(WRITER);
    const READER_MASK: usize = std.math.max_int(Count) << @ctz(READER);
    const Count = std.meta.Int(.unsigned, @div_floor(@bitSizeOf(usize) - 1, 2));

    pub fn try_lock(rwl: *DefaultRwLock) bool {
        if (rwl.mutex.try_lock()) {
            const state = @atomicLoad(usize, &rwl.state, .seq_cst);
            if (state & READER_MASK == 0) {
                _ = @atomicRmw(usize, &rwl.state, .Or, IS_WRITING, .seq_cst);
                return true;
            }

            rwl.mutex.unlock();
        }

        return false;
    }

    pub fn lock(rwl: *DefaultRwLock) void {
        _ = @atomicRmw(usize, &rwl.state, .Add, WRITER, .seq_cst);
        rwl.mutex.lock();

        const state = @atomicRmw(usize, &rwl.state, .Add, IS_WRITING -% WRITER, .seq_cst);
        if (state & READER_MASK != 0)
            rwl.semaphore.wait();
    }

    pub fn unlock(rwl: *DefaultRwLock) void {
        _ = @atomicRmw(usize, &rwl.state, .And, ~IS_WRITING, .seq_cst);
        rwl.mutex.unlock();
    }

    pub fn try_lock_shared(rwl: *DefaultRwLock) bool {
        const state = @atomicLoad(usize, &rwl.state, .seq_cst);
        if (state & (IS_WRITING | WRITER_MASK) == 0) {
            _ = @cmpxchg_strong(
                usize,
                &rwl.state,
                state,
                state + READER,
                .seq_cst,
                .seq_cst,
            ) orelse return true;
        }

        if (rwl.mutex.try_lock()) {
            _ = @atomicRmw(usize, &rwl.state, .Add, READER, .seq_cst);
            rwl.mutex.unlock();
            return true;
        }

        return false;
    }

    pub fn lock_shared(rwl: *DefaultRwLock) void {
        var state = @atomicLoad(usize, &rwl.state, .seq_cst);
        while (state & (IS_WRITING | WRITER_MASK) == 0) {
            state = @cmpxchg_weak(
                usize,
                &rwl.state,
                state,
                state + READER,
                .seq_cst,
                .seq_cst,
            ) orelse return;
        }

        rwl.mutex.lock();
        _ = @atomicRmw(usize, &rwl.state, .Add, READER, .seq_cst);
        rwl.mutex.unlock();
    }

    pub fn unlock_shared(rwl: *DefaultRwLock) void {
        const state = @atomicRmw(usize, &rwl.state, .Sub, READER, .seq_cst);

        if ((state & READER_MASK == READER) and (state & IS_WRITING != 0))
            rwl.semaphore.post();
    }
};

test "DefaultRwLock - internal state" {
    var rwl = DefaultRwLock{};

    // The following failed prior to the fix for Issue #13163,
    // where the WRITER flag was subtracted by the lock method.

    rwl.lock();
    rwl.unlock();
    try testing.expect_equal(rwl, DefaultRwLock{});
}

test "smoke test" {
    var rwl = RwLock{};

    rwl.lock();
    try testing.expect(!rwl.try_lock());
    try testing.expect(!rwl.try_lock_shared());
    rwl.unlock();

    try testing.expect(rwl.try_lock());
    try testing.expect(!rwl.try_lock());
    try testing.expect(!rwl.try_lock_shared());
    rwl.unlock();

    rwl.lock_shared();
    try testing.expect(!rwl.try_lock());
    try testing.expect(rwl.try_lock_shared());
    rwl.unlock_shared();
    rwl.unlock_shared();

    try testing.expect(rwl.try_lock_shared());
    try testing.expect(!rwl.try_lock());
    try testing.expect(rwl.try_lock_shared());
    rwl.unlock_shared();
    rwl.unlock_shared();

    rwl.lock();
    rwl.unlock();
}

test "concurrent access" {
    if (builtin.single_threaded)
        return;

    const num_writers: usize = 2;
    const num_readers: usize = 4;
    const num_writes: usize = 10000;
    const num_reads: usize = num_writes * 2;

    const Runner = struct {
        const Self = @This();

        rwl: RwLock = .{},
        writes: usize = 0,
        reads: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        term1: usize = 0,
        term2: usize = 0,
        term_sum: usize = 0,

        fn reader(self: *Self) !void {
            while (true) {
                self.rwl.lock_shared();
                defer self.rwl.unlock_shared();

                if (self.writes >= num_writes or self.reads.load(.unordered) >= num_reads)
                    break;

                try self.check();

                _ = self.reads.fetch_add(1, .monotonic);
            }
        }

        fn writer(self: *Self, thread_idx: usize) !void {
            var prng = std.Random.DefaultPrng.init(thread_idx);
            var rnd = prng.random();

            while (true) {
                self.rwl.lock();
                defer self.rwl.unlock();

                if (self.writes >= num_writes)
                    break;

                try self.check();

                const term1 = rnd.int(usize);
                self.term1 = term1;
                try std.Thread.yield();

                const term2 = rnd.int(usize);
                self.term2 = term2;
                try std.Thread.yield();

                self.term_sum = term1 +% term2;
                self.writes += 1;
            }
        }

        fn check(self: *const Self) !void {
            const term_sum = self.term_sum;
            try std.Thread.yield();

            const term2 = self.term2;
            try std.Thread.yield();

            const term1 = self.term1;
            try testing.expect_equal(term_sum, term1 +% term2);
        }
    };

    var runner = Runner{};
    var threads: [num_writers + num_readers]std.Thread = undefined;

    for (threads[0..num_writers], 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Runner.writer, .{ &runner, i });
    for (threads[num_writers..]) |*t| t.* = try std.Thread.spawn(.{}, Runner.reader, .{&runner});

    for (threads) |t| t.join();

    try testing.expect_equal(num_writes, runner.writes);

    //std.debug.print("reads={}\n", .{ runner.reads.load(.unordered)});
}
