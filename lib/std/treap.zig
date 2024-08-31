const std = @import("std.zig");
const assert = std.debug.assert;
const testing = std.testing;
const Order = std.math.Order;

pub fn Treap(comptime Key: type, comptime compare_fn: anytype) type {
    return struct {
        const Self = @This();

        // Allow for compare_fn to be fn (anytype, anytype) anytype
        // which allows the convenient use of std.math.order.
        fn compare(a: Key, b: Key) Order {
            return compare_fn(a, b);
        }

        root: ?*Node = null,
        prng: Prng = .{},

        /// A customized pseudo random number generator for the treap.
        /// This just helps reducing the memory size of the treap itself
        /// as std.Random.DefaultPrng requires larger state (while producing better entropy for randomness to be fair).
        const Prng = struct {
            xorshift: usize = 0,

            fn random(self: *Prng, seed: usize) usize {
                // Lazily seed the prng state
                if (self.xorshift == 0) {
                    self.xorshift = seed;
                }

                // Since we're using usize, decide the shifts by the integer's bit width.
                const shifts = switch (@bitSizeOf(usize)) {
                    64 => .{ 13, 7, 17 },
                    32 => .{ 13, 17, 5 },
                    16 => .{ 7, 9, 8 },
                    else => @compile_error("platform not supported"),
                };

                self.xorshift ^= self.xorshift >> shifts[0];
                self.xorshift ^= self.xorshift << shifts[1];
                self.xorshift ^= self.xorshift >> shifts[2];

                assert(self.xorshift != 0);
                return self.xorshift;
            }
        };

        /// A Node represents an item or point in the treap with a uniquely associated key.
        pub const Node = struct {
            key: Key,
            priority: usize,
            parent: ?*Node,
            children: [2]?*Node,
        };

        /// Returns the smallest Node by key in the treap if there is one.
        /// Use `get_entry_for_existing()` to replace/remove this Node from the treap.
        pub fn get_min(self: Self) ?*Node {
            var node = self.root;
            while (node) |current| {
                node = current.children[0] orelse break;
            }
            return node;
        }

        /// Returns the largest Node by key in the treap if there is one.
        /// Use `get_entry_for_existing()` to replace/remove this Node from the treap.
        pub fn get_max(self: Self) ?*Node {
            var node = self.root;
            while (node) |current| {
                node = current.children[1] orelse break;
            }
            return node;
        }

        /// Lookup the Entry for the given key in the treap.
        /// The Entry act's as a slot in the treap to insert/replace/remove the node associated with the key.
        pub fn get_entry_for(self: *Self, key: Key) Entry {
            var parent: ?*Node = undefined;
            const node = self.find(key, &parent);

            return Entry{
                .key = key,
                .treap = self,
                .node = node,
                .context = .{ .inserted_under = parent },
            };
        }

        /// Get an entry for a Node that currently exists in the treap.
        /// It is undefined behavior if the Node is not currently inserted in the treap.
        /// The Entry act's as a slot in the treap to insert/replace/remove the node associated with the key.
        pub fn get_entry_for_existing(self: *Self, node: *Node) Entry {
            assert(node.priority != 0);

            return Entry{
                .key = node.key,
                .treap = self,
                .node = node,
                .context = .{ .inserted_under = node.parent },
            };
        }

        /// An Entry represents a slot in the treap associated with a given key.
        pub const Entry = struct {
            /// The associated key for this entry.
            key: Key,
            /// A reference to the treap this entry is apart of.
            treap: *Self,
            /// The current node at this entry.
            node: ?*Node,
            /// The current state of the entry.
            context: union(enum) {
                /// A find() was called for this entry and the position in the treap is known.
                inserted_under: ?*Node,
                /// The entry's node was removed from the treap and a lookup must occur again for modification.
                removed,
            },

            /// Update's the Node at this Entry in the treap with the new node.
            pub fn set(self: *Entry, new_node: ?*Node) void {
                // Update the entry's node reference after updating the treap below.
                defer self.node = new_node;

                if (self.node) |old| {
                    if (new_node) |new| {
                        self.treap.replace(old, new);
                        return;
                    }

                    self.treap.remove(old);
                    self.context = .removed;
                    return;
                }

                if (new_node) |new| {
                    // A previous treap.remove() could have rebalanced the nodes
                    // so when inserting after a removal, we have to re-lookup the parent again.
                    // This lookup shouldn't find a node because we're yet to insert it..
                    var parent: ?*Node = undefined;
                    switch (self.context) {
                        .inserted_under => |p| parent = p,
                        .removed => assert(self.treap.find(self.key, &parent) == null),
                    }

                    self.treap.insert(self.key, parent, new);
                    self.context = .{ .inserted_under = parent };
                }
            }
        };

        fn find(self: Self, key: Key, parent_ref: *?*Node) ?*Node {
            var node = self.root;
            parent_ref.* = null;

            // basic binary search while tracking the parent.
            while (node) |current| {
                const order = compare(key, current.key);
                if (order == .eq) break;

                parent_ref.* = current;
                node = current.children[@int_from_bool(order == .gt)];
            }

            return node;
        }

        fn insert(self: *Self, key: Key, parent: ?*Node, node: *Node) void {
            // generate a random priority & prepare the node to be inserted into the tree
            node.key = key;
            node.priority = self.prng.random(@int_from_ptr(node));
            node.parent = parent;
            node.children = [_]?*Node{ null, null };

            // point the parent at the new node
            const link = if (parent) |p| &p.children[@int_from_bool(compare(key, p.key) == .gt)] else &self.root;
            assert(link.* == null);
            link.* = node;

            // rotate the node up into the tree to balance it according to its priority
            while (node.parent) |p| {
                if (p.priority <= node.priority) break;

                const is_right = p.children[1] == node;
                assert(p.children[@int_from_bool(is_right)] == node);

                const rotate_right = !is_right;
                self.rotate(p, rotate_right);
            }
        }

        fn replace(self: *Self, old: *Node, new: *Node) void {
            // copy over the values from the old node
            new.key = old.key;
            new.priority = old.priority;
            new.parent = old.parent;
            new.children = old.children;

            // point the parent at the new node
            const link = if (old.parent) |p| &p.children[@int_from_bool(p.children[1] == old)] else &self.root;
            assert(link.* == old);
            link.* = new;

            // point the children's parent at the new node
            for (old.children) |child_node| {
                const child = child_node orelse continue;
                assert(child.parent == old);
                child.parent = new;
            }
        }

        fn remove(self: *Self, node: *Node) void {
            // rotate the node down to be a leaf of the tree for removal, respecting priorities.
            while (node.children[0] orelse node.children[1]) |_| {
                self.rotate(node, rotate_right: {
                    const right = node.children[1] orelse break :rotate_right true;
                    const left = node.children[0] orelse break :rotate_right false;
                    break :rotate_right (left.priority < right.priority);
                });
            }

            // node is a now a leaf; remove by nulling out the parent's reference to it.
            const link = if (node.parent) |p| &p.children[@int_from_bool(p.children[1] == node)] else &self.root;
            assert(link.* == node);
            link.* = null;

            // clean up after ourselves
            node.priority = 0;
            node.parent = null;
            node.children = [_]?*Node{ null, null };
        }

        fn rotate(self: *Self, node: *Node, right: bool) void {
            // if right, converts the following:
            //      parent -> (node (target YY adjacent) XX)
            //      parent -> (target YY (node adjacent XX))
            //
            // if left (!right), converts the following:
            //      parent -> (node (target YY adjacent) XX)
            //      parent -> (target YY (node adjacent XX))
            const parent = node.parent;
            const target = node.children[@int_from_bool(!right)] orelse unreachable;
            const adjacent = target.children[@int_from_bool(right)];

            // rotate the children
            target.children[@int_from_bool(right)] = node;
            node.children[@int_from_bool(!right)] = adjacent;

            // rotate the parents
            node.parent = target;
            target.parent = parent;
            if (adjacent) |adj| adj.parent = node;

            // fix the parent link
            const link = if (parent) |p| &p.children[@int_from_bool(p.children[1] == node)] else &self.root;
            assert(link.* == node);
            link.* = target;
        }

        pub const InorderIterator = struct {
            current: ?*Node,
            previous: ?*Node = null,

            pub fn next(it: *InorderIterator) ?*Node {
                while (true) {
                    if (it.current) |current| {
                        const previous = it.previous;
                        it.previous = current;
                        if (previous == current.parent) {
                            if (current.children[0]) |left_child| {
                                it.current = left_child;
                            } else {
                                if (current.children[1]) |right_child| {
                                    it.current = right_child;
                                } else {
                                    it.current = current.parent;
                                }
                                return current;
                            }
                        } else if (previous == current.children[0]) {
                            if (current.children[1]) |right_child| {
                                it.current = right_child;
                            } else {
                                it.current = current.parent;
                            }
                            return current;
                        } else {
                            std.debug.assert(previous == current.children[1]);
                            it.current = current.parent;
                        }
                    } else {
                        return null;
                    }
                }
            }
        };

        pub fn inorder_iterator(self: *Self) InorderIterator {
            return .{ .current = self.root };
        }
    };
}

// For iterating a slice in a random order
// https://lemire.me/blog/2017/09/18/visiting-all-values-in-an-array-exactly-once-in-random-order/
fn SliceIterRandomOrder(comptime T: type) type {
    return struct {
        rng: std.Random,
        slice: []T,
        index: usize = undefined,
        offset: usize = undefined,
        co_prime: usize,

        const Self = @This();

        pub fn init(slice: []T, rng: std.Random) Self {
            return Self{
                .rng = rng,
                .slice = slice,
                .co_prime = blk: {
                    if (slice.len == 0) break :blk 0;
                    var prime = slice.len / 2;
                    while (prime < slice.len) : (prime += 1) {
                        var gcd = [_]usize{ prime, slice.len };
                        while (gcd[1] != 0) {
                            const temp = gcd;
                            gcd = [_]usize{ temp[1], temp[0] % temp[1] };
                        }
                        if (gcd[0] == 1) break;
                    }
                    break :blk prime;
                },
            };
        }

        pub fn reset(self: *Self) void {
            self.index = 0;
            self.offset = self.rng.int(usize);
        }

        pub fn next(self: *Self) ?*T {
            if (self.index >= self.slice.len) return null;
            defer self.index += 1;
            return &self.slice[((self.index *% self.co_prime) +% self.offset) % self.slice.len];
        }
    };
}

const TestTreap = Treap(u64, std.math.order);
const TestNode = TestTreap.Node;

test "insert, find, replace, remove" {
    var treap = TestTreap{};
    var nodes: [10]TestNode = undefined;

    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    var iter = SliceIterRandomOrder(TestNode).init(&nodes, prng.random());

    // insert check
    iter.reset();
    while (iter.next()) |node| {
        const key = prng.random().int(u64);

        // make sure the current entry is empty.
        var entry = treap.get_entry_for(key);
        try testing.expect_equal(entry.key, key);
        try testing.expect_equal(entry.node, null);

        // insert the entry and make sure the fields are correct.
        entry.set(node);
        try testing.expect_equal(node.key, key);
        try testing.expect_equal(entry.key, key);
        try testing.expect_equal(entry.node, node);
    }

    // find check
    iter.reset();
    while (iter.next()) |node| {
        const key = node.key;

        // find the entry by-key and by-node after having been inserted.
        const entry = treap.get_entry_for(node.key);
        try testing.expect_equal(entry.key, key);
        try testing.expect_equal(entry.node, node);
        try testing.expect_equal(entry.node, treap.get_entry_for_existing(node).node);
    }

    // in-order iterator check
    {
        var it = treap.inorder_iterator();
        var last_key: u64 = 0;
        while (it.next()) |node| {
            try std.testing.expect(node.key >= last_key);
            last_key = node.key;
        }
    }

    // replace check
    iter.reset();
    while (iter.next()) |node| {
        const key = node.key;

        // find the entry by node since we already know it exists
        var entry = treap.get_entry_for_existing(node);
        try testing.expect_equal(entry.key, key);
        try testing.expect_equal(entry.node, node);

        var stub_node: TestNode = undefined;

        // replace the node with a stub_node and ensure future finds point to the stub_node.
        entry.set(&stub_node);
        try testing.expect_equal(entry.node, &stub_node);
        try testing.expect_equal(entry.node, treap.get_entry_for(key).node);
        try testing.expect_equal(entry.node, treap.get_entry_for_existing(&stub_node).node);

        // replace the stub_node back to the node and ensure future finds point to the old node.
        entry.set(node);
        try testing.expect_equal(entry.node, node);
        try testing.expect_equal(entry.node, treap.get_entry_for(key).node);
        try testing.expect_equal(entry.node, treap.get_entry_for_existing(node).node);
    }

    // remove check
    iter.reset();
    while (iter.next()) |node| {
        const key = node.key;

        // find the entry by node since we already know it exists
        var entry = treap.get_entry_for_existing(node);
        try testing.expect_equal(entry.key, key);
        try testing.expect_equal(entry.node, node);

        // remove the node at the entry and ensure future finds point to it being removed.
        entry.set(null);
        try testing.expect_equal(entry.node, null);
        try testing.expect_equal(entry.node, treap.get_entry_for(key).node);

        // insert the node back and ensure future finds point to the inserted node
        entry.set(node);
        try testing.expect_equal(entry.node, node);
        try testing.expect_equal(entry.node, treap.get_entry_for(key).node);
        try testing.expect_equal(entry.node, treap.get_entry_for_existing(node).node);

        // remove the node again and make sure it was cleared after the insert
        entry.set(null);
        try testing.expect_equal(entry.node, null);
        try testing.expect_equal(entry.node, treap.get_entry_for(key).node);
    }
}
