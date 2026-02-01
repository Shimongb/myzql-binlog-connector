//! Bounded MPSC Queue
//!
//! A bounded, multi-producer single-consumer queue backed by a ring buffer.
//! Uses mutex + condition variables for blocking push/pop semantics.
//! Supports graceful shutdown via close().

const std = @import("std");

pub fn MpscQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        buffer: []T,
        head: usize, // next write position (producer)
        tail: usize, // next read position (consumer)
        count: usize,
        capacity: usize,
        closed: bool,
        mutex: std.Thread.Mutex,
        not_empty: std.Thread.Condition,
        not_full: std.Thread.Condition,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
            const buffer = try allocator.alloc(T, capacity);
            return Self{
                .buffer = buffer,
                .head = 0,
                .tail = 0,
                .count = 0,
                .capacity = capacity,
                .closed = false,
                .mutex = .{},
                .not_empty = .{},
                .not_full = .{},
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);
        }

        /// Push an item. Blocks if full. Returns false if queue is closed.
        pub fn push(self: *Self, item: T) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.count == self.capacity and !self.closed) {
                self.not_full.wait(&self.mutex);
            }

            if (self.closed) return false;

            self.buffer[self.head] = item;
            self.head = (self.head + 1) % self.capacity;
            self.count += 1;

            self.not_empty.signal();
            return true;
        }

        /// Pop an item. Blocks if empty. Returns null if queue is closed AND empty.
        pub fn pop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.count == 0 and !self.closed) {
                self.not_empty.wait(&self.mutex);
            }

            if (self.count == 0) return null; // closed and empty

            const item = self.buffer[self.tail];
            self.tail = (self.tail + 1) % self.capacity;
            self.count -= 1;

            self.not_full.signal();
            return item;
        }

        /// Close the queue. Wakes all waiting threads.
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.closed = true;
            self.not_empty.broadcast();
            self.not_full.broadcast();
        }
    };
}

test "basic push pop" {
    var q = try MpscQueue(u32).init(std.testing.allocator, 4);
    defer q.deinit();

    try std.testing.expect(q.push(1));
    try std.testing.expect(q.push(2));
    try std.testing.expect(q.push(3));

    try std.testing.expectEqual(@as(?u32, 1), q.pop());
    try std.testing.expectEqual(@as(?u32, 2), q.pop());
    try std.testing.expectEqual(@as(?u32, 3), q.pop());
}

test "close returns null on empty" {
    var q = try MpscQueue(u32).init(std.testing.allocator, 4);
    defer q.deinit();

    try std.testing.expect(q.push(10));
    q.close();

    // Can still drain
    try std.testing.expectEqual(@as(?u32, 10), q.pop());
    // Now returns null
    try std.testing.expectEqual(@as(?u32, null), q.pop());
}

test "close prevents push" {
    var q = try MpscQueue(u32).init(std.testing.allocator, 4);
    defer q.deinit();

    q.close();
    try std.testing.expect(!q.push(1));
}

test "concurrent push pop" {
    var q = try MpscQueue(u32).init(std.testing.allocator, 8);
    defer q.deinit();

    const producer = try std.Thread.spawn(.{}, struct {
        fn run(queue: *MpscQueue(u32)) void {
            var i: u32 = 0;
            while (i < 100) : (i += 1) {
                if (!queue.push(i)) break;
            }
            queue.close();
        }
    }.run, .{&q});

    var sum: u64 = 0;
    var count: u32 = 0;
    while (q.pop()) |val| {
        sum += val;
        count += 1;
    }

    producer.join();

    try std.testing.expectEqual(@as(u32, 100), count);
    try std.testing.expectEqual(@as(u64, 4950), sum); // sum of 0..99
}
