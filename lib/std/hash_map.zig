const std = @import("std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const auto_hash = std.hash.auto_hash;
const math = std.math;
const mem = std.mem;
const Allocator = mem.Allocator;
const Wyhash = std.hash.Wyhash;

pub fn get_auto_hash_fn(comptime K: type, comptime Context: type) (fn (Context, K) u64) {
    comptime {
        assert(@hasDecl(std, "StringHashMap")); // detect when the following message needs updated
        if (K == []const u8) {
            @compile_error("std.auto_hash.auto_hash does not allow slices here (" ++
                @type_name(K) ++
                ") because the intent is unclear. " ++
                "Consider using std.StringHashMap for hashing the contents of []const u8. " ++
                "Alternatively, consider using std.auto_hash.hash or providing your own hash function instead.");
        }
    }

    return struct {
        fn hash(ctx: Context, key: K) u64 {
            _ = ctx;
            if (std.meta.has_unique_representation(K)) {
                return Wyhash.hash(0, std.mem.as_bytes(&key));
            } else {
                var hasher = Wyhash.init(0);
                auto_hash(&hasher, key);
                return hasher.final();
            }
        }
    }.hash;
}

pub fn get_auto_eql_fn(comptime K: type, comptime Context: type) (fn (Context, K, K) bool) {
    return struct {
        fn eql(ctx: Context, a: K, b: K) bool {
            _ = ctx;
            return std.meta.eql(a, b);
        }
    }.eql;
}

pub fn AutoHashMap(comptime K: type, comptime V: type) type {
    return HashMap(K, V, AutoContext(K), default_max_load_percentage);
}

pub fn AutoHashMapUnmanaged(comptime K: type, comptime V: type) type {
    return HashMapUnmanaged(K, V, AutoContext(K), default_max_load_percentage);
}

pub fn AutoContext(comptime K: type) type {
    return struct {
        pub const hash = get_auto_hash_fn(K, @This());
        pub const eql = get_auto_eql_fn(K, @This());
    };
}

/// Builtin hashmap for strings as keys.
/// Key memory is managed by the caller.  Keys and values
/// will not automatically be freed.
pub fn StringHashMap(comptime V: type) type {
    return HashMap([]const u8, V, StringContext, default_max_load_percentage);
}

/// Key memory is managed by the caller.  Keys and values
/// will not automatically be freed.
pub fn StringHashMapUnmanaged(comptime V: type) type {
    return HashMapUnmanaged([]const u8, V, StringContext, default_max_load_percentage);
}

pub const StringContext = struct {
    pub fn hash(self: @This(), s: []const u8) u64 {
        _ = self;
        return hash_string(s);
    }
    pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
        _ = self;
        return eql_string(a, b);
    }
};

pub fn eql_string(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, a, b);
}

pub fn hash_string(s: []const u8) u64 {
    return std.hash.Wyhash.hash(0, s);
}

pub const StringIndexContext = struct {
    bytes: *const std.ArrayListUnmanaged(u8),

    pub fn eql(_: @This(), a: u32, b: u32) bool {
        return a == b;
    }

    pub fn hash(ctx: @This(), key: u32) u64 {
        return hash_string(mem.slice_to(ctx.bytes.items[key..], 0));
    }
};

pub const StringIndexAdapter = struct {
    bytes: *const std.ArrayListUnmanaged(u8),

    pub fn eql(ctx: @This(), a: []const u8, b: u32) bool {
        return mem.eql(u8, a, mem.slice_to(ctx.bytes.items[b..], 0));
    }

    pub fn hash(_: @This(), adapted_key: []const u8) u64 {
        assert(mem.index_of_scalar(u8, adapted_key, 0) == null);
        return hash_string(adapted_key);
    }
};

pub const default_max_load_percentage = 80;

/// This function issues a compile error with a helpful message if there
/// is a problem with the provided context type.  A context must have the following
/// member functions:
///   - hash(self, PseudoKey) Hash
///   - eql(self, PseudoKey, Key) bool
///
/// If you are passing a context to a *Adapted function, PseudoKey is the type
/// of the key parameter.  Otherwise, when creating a HashMap or HashMapUnmanaged
/// type, PseudoKey = Key = K.
pub fn verify_context(
    comptime RawContext: type,
    comptime PseudoKey: type,
    comptime Key: type,
    comptime Hash: type,
    comptime is_array: bool,
) void {
    comptime {
        var allow_const_ptr = false;
        var allow_mutable_ptr = false;
        // Context is the actual namespace type.  RawContext may be a pointer to Context.
        var Context = RawContext;
        // Make sure the context is a namespace type which may have member functions
        switch (@typeInfo(Context)) {
            .Struct, .Union, .Enum => {},
            // Special-case .Opaque for a better error message
            .Opaque => @compile_error("Hash context must be a type with hash and eql member functions.  Cannot use " ++ @type_name(Context) ++ " because it is opaque.  Use a pointer instead."),
            .Pointer => |ptr| {
                if (ptr.size != .One) {
                    @compile_error("Hash context must be a type with hash and eql member functions.  Cannot use " ++ @type_name(Context) ++ " because it is not a single pointer.");
                }
                Context = ptr.child;
                allow_const_ptr = true;
                allow_mutable_ptr = !ptr.is_const;
                switch (@typeInfo(Context)) {
                    .Struct, .Union, .Enum, .Opaque => {},
                    else => @compile_error("Hash context must be a type with hash and eql member functions.  Cannot use " ++ @type_name(Context)),
                }
            },
            else => @compile_error("Hash context must be a type with hash and eql member functions.  Cannot use " ++ @type_name(Context)),
        }

        // Keep track of multiple errors so we can report them all.
        var errors: []const u8 = "";

        // Put common errors here, they will only be evaluated
        // if the error is actually triggered.
        const lazy = struct {
            const prefix = "\n  ";
            const deep_prefix = prefix ++ "  ";
            const hash_signature = "fn (self, " ++ @type_name(PseudoKey) ++ ") " ++ @type_name(Hash);
            const index_param = if (is_array) ", b_index: usize" else "";
            const eql_signature = "fn (self, " ++ @type_name(PseudoKey) ++ ", " ++
                @type_name(Key) ++ index_param ++ ") bool";
            const err_invalid_hash_signature = prefix ++ @type_name(Context) ++ ".hash must be " ++ hash_signature ++
                deep_prefix ++ "but is actually " ++ @type_name(@TypeOf(Context.hash));
            const err_invalid_eql_signature = prefix ++ @type_name(Context) ++ ".eql must be " ++ eql_signature ++
                deep_prefix ++ "but is actually " ++ @type_name(@TypeOf(Context.eql));
        };

        // Verify Context.hash(self, PseudoKey) => Hash
        if (@hasDecl(Context, "hash")) {
            const hash = Context.hash;
            const info = @typeInfo(@TypeOf(hash));
            if (info == .Fn) {
                const func = info.Fn;
                if (func.params.len != 2) {
                    errors = errors ++ lazy.err_invalid_hash_signature;
                } else {
                    var emitted_signature = false;
                    if (func.params[0].type) |Self| {
                        if (Self == Context) {
                            // pass, this is always fine.
                        } else if (Self == *const Context) {
                            if (!allow_const_ptr) {
                                if (!emitted_signature) {
                                    errors = errors ++ lazy.err_invalid_hash_signature;
                                    emitted_signature = true;
                                }
                                errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context) ++ ", but is " ++ @type_name(Self);
                                errors = errors ++ lazy.deep_prefix ++ "Note: Cannot be a pointer because it is passed by value.";
                            }
                        } else if (Self == *Context) {
                            if (!allow_mutable_ptr) {
                                if (!emitted_signature) {
                                    errors = errors ++ lazy.err_invalid_hash_signature;
                                    emitted_signature = true;
                                }
                                if (!allow_const_ptr) {
                                    errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context) ++ ", but is " ++ @type_name(Self);
                                    errors = errors ++ lazy.deep_prefix ++ "Note: Cannot be a pointer because it is passed by value.";
                                } else {
                                    errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context) ++ " or " ++ @type_name(*const Context) ++ ", but is " ++ @type_name(Self);
                                    errors = errors ++ lazy.deep_prefix ++ "Note: Cannot be non-const because it is passed by const pointer.";
                                }
                            }
                        } else {
                            if (!emitted_signature) {
                                errors = errors ++ lazy.err_invalid_hash_signature;
                                emitted_signature = true;
                            }
                            errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context);
                            if (allow_const_ptr) {
                                errors = errors ++ " or " ++ @type_name(*const Context);
                                if (allow_mutable_ptr) {
                                    errors = errors ++ " or " ++ @type_name(*Context);
                                }
                            }
                            errors = errors ++ ", but is " ++ @type_name(Self);
                        }
                    }
                    if (func.params[1].type != null and func.params[1].type.? != PseudoKey) {
                        if (!emitted_signature) {
                            errors = errors ++ lazy.err_invalid_hash_signature;
                            emitted_signature = true;
                        }
                        errors = errors ++ lazy.deep_prefix ++ "Second parameter must be " ++ @type_name(PseudoKey) ++ ", but is " ++ @type_name(func.params[1].type.?);
                    }
                    if (func.return_type != null and func.return_type.? != Hash) {
                        if (!emitted_signature) {
                            errors = errors ++ lazy.err_invalid_hash_signature;
                            emitted_signature = true;
                        }
                        errors = errors ++ lazy.deep_prefix ++ "Return type must be " ++ @type_name(Hash) ++ ", but was " ++ @type_name(func.return_type.?);
                    }
                    // If any of these are generic (null), we cannot verify them.
                    // The call sites check the return type, but cannot check the
                    // parameters.  This may cause compile errors with generic hash/eql functions.
                }
            } else {
                errors = errors ++ lazy.err_invalid_hash_signature;
            }
        } else {
            errors = errors ++ lazy.prefix ++ @type_name(Context) ++ " must declare a pub hash function with signature " ++ lazy.hash_signature;
        }

        // Verify Context.eql(self, PseudoKey, Key) => bool
        if (@hasDecl(Context, "eql")) {
            const eql = Context.eql;
            const info = @typeInfo(@TypeOf(eql));
            if (info == .Fn) {
                const func = info.Fn;
                const args_len = if (is_array) 4 else 3;
                if (func.params.len != args_len) {
                    errors = errors ++ lazy.err_invalid_eql_signature;
                } else {
                    var emitted_signature = false;
                    if (func.params[0].type) |Self| {
                        if (Self == Context) {
                            // pass, this is always fine.
                        } else if (Self == *const Context) {
                            if (!allow_const_ptr) {
                                if (!emitted_signature) {
                                    errors = errors ++ lazy.err_invalid_eql_signature;
                                    emitted_signature = true;
                                }
                                errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context) ++ ", but is " ++ @type_name(Self);
                                errors = errors ++ lazy.deep_prefix ++ "Note: Cannot be a pointer because it is passed by value.";
                            }
                        } else if (Self == *Context) {
                            if (!allow_mutable_ptr) {
                                if (!emitted_signature) {
                                    errors = errors ++ lazy.err_invalid_eql_signature;
                                    emitted_signature = true;
                                }
                                if (!allow_const_ptr) {
                                    errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context) ++ ", but is " ++ @type_name(Self);
                                    errors = errors ++ lazy.deep_prefix ++ "Note: Cannot be a pointer because it is passed by value.";
                                } else {
                                    errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context) ++ " or " ++ @type_name(*const Context) ++ ", but is " ++ @type_name(Self);
                                    errors = errors ++ lazy.deep_prefix ++ "Note: Cannot be non-const because it is passed by const pointer.";
                                }
                            }
                        } else {
                            if (!emitted_signature) {
                                errors = errors ++ lazy.err_invalid_eql_signature;
                                emitted_signature = true;
                            }
                            errors = errors ++ lazy.deep_prefix ++ "First parameter must be " ++ @type_name(Context);
                            if (allow_const_ptr) {
                                errors = errors ++ " or " ++ @type_name(*const Context);
                                if (allow_mutable_ptr) {
                                    errors = errors ++ " or " ++ @type_name(*Context);
                                }
                            }
                            errors = errors ++ ", but is " ++ @type_name(Self);
                        }
                    }
                    if (func.params[1].type.? != PseudoKey) {
                        if (!emitted_signature) {
                            errors = errors ++ lazy.err_invalid_eql_signature;
                            emitted_signature = true;
                        }
                        errors = errors ++ lazy.deep_prefix ++ "Second parameter must be " ++ @type_name(PseudoKey) ++ ", but is " ++ @type_name(func.params[1].type.?);
                    }
                    if (func.params[2].type.? != Key) {
                        if (!emitted_signature) {
                            errors = errors ++ lazy.err_invalid_eql_signature;
                            emitted_signature = true;
                        }
                        errors = errors ++ lazy.deep_prefix ++ "Third parameter must be " ++ @type_name(Key) ++ ", but is " ++ @type_name(func.params[2].type.?);
                    }
                    if (func.return_type.? != bool) {
                        if (!emitted_signature) {
                            errors = errors ++ lazy.err_invalid_eql_signature;
                            emitted_signature = true;
                        }
                        errors = errors ++ lazy.deep_prefix ++ "Return type must be bool, but was " ++ @type_name(func.return_type.?);
                    }
                    // If any of these are generic (null), we cannot verify them.
                    // The call sites check the return type, but cannot check the
                    // parameters.  This may cause compile errors with generic hash/eql functions.
                }
            } else {
                errors = errors ++ lazy.err_invalid_eql_signature;
            }
        } else {
            errors = errors ++ lazy.prefix ++ @type_name(Context) ++ " must declare a pub eql function with signature " ++ lazy.eql_signature;
        }

        if (errors.len != 0) {
            // errors begins with a newline (from lazy.prefix)
            @compile_error("Problems found with hash context type " ++ @type_name(Context) ++ ":" ++ errors);
        }
    }
}

/// General purpose hash table.
/// No order is guaranteed and any modification invalidates live iterators.
/// It provides fast operations (lookup, insertion, deletion) with quite high
/// load factors (up to 80% by default) for low memory usage.
/// For a hash map that can be initialized directly that does not store an Allocator
/// field, see `HashMapUnmanaged`.
/// If iterating over the table entries is a strong usecase and needs to be fast,
/// prefer the alternative `std.ArrayHashMap`.
/// Context must be a struct type with two member functions:
///   hash(self, K) u64
///   eql(self, K, K) bool
/// Adapted variants of many functions are provided.  These variants
/// take a pseudo key instead of a key.  Their context must have the functions:
///   hash(self, PseudoKey) u64
///   eql(self, PseudoKey, K) bool
pub fn HashMap(
    comptime K: type,
    comptime V: type,
    comptime Context: type,
    comptime max_load_percentage: u64,
) type {
    return struct {
        unmanaged: Unmanaged,
        allocator: Allocator,
        ctx: Context,

        comptime {
            verify_context(Context, K, K, u64, false);
        }

        /// The type of the unmanaged hash map underlying this wrapper
        pub const Unmanaged = HashMapUnmanaged(K, V, Context, max_load_percentage);
        /// An entry, containing pointers to a key and value stored in the map
        pub const Entry = Unmanaged.Entry;
        /// A copy of a key and value which are no longer in the map
        pub const KV = Unmanaged.KV;
        /// The integer type that is the result of hashing
        pub const Hash = Unmanaged.Hash;
        /// The iterator type returned by iterator()
        pub const Iterator = Unmanaged.Iterator;

        pub const KeyIterator = Unmanaged.KeyIterator;
        pub const ValueIterator = Unmanaged.ValueIterator;

        /// The integer type used to store the size of the map
        pub const Size = Unmanaged.Size;
        /// The type returned from get_or_put and variants
        pub const GetOrPutResult = Unmanaged.GetOrPutResult;

        const Self = @This();

        /// Create a managed hash map with an empty context.
        /// If the context is not zero-sized, you must use
        /// init_context(allocator, ctx) instead.
        pub fn init(allocator: Allocator) Self {
            if (@size_of(Context) != 0) {
                @compile_error("Context must be specified! Call init_context(allocator, ctx) instead.");
            }
            return .{
                .unmanaged = .{},
                .allocator = allocator,
                .ctx = undefined, // ctx is zero-sized so this is safe.
            };
        }

        /// Create a managed hash map with a context
        pub fn init_context(allocator: Allocator, ctx: Context) Self {
            return .{
                .unmanaged = .{},
                .allocator = allocator,
                .ctx = ctx,
            };
        }

        /// Puts the hash map into a state where any method call that would
        /// cause an existing key or value pointer to become invalidated will
        /// instead trigger an assertion.
        ///
        /// An additional call to `lock_pointers` in such state also triggers an
        /// assertion.
        ///
        /// `unlock_pointers` returns the hash map to the previous state.
        pub fn lock_pointers(self: *Self) void {
            self.unmanaged.lock_pointers();
        }

        /// Undoes a call to `lock_pointers`.
        pub fn unlock_pointers(self: *Self) void {
            self.unmanaged.unlock_pointers();
        }

        /// Release the backing array and invalidate this map.
        /// This does *not* deinit keys, values, or the context!
        /// If your keys or values need to be released, ensure
        /// that that is done before calling this function.
        pub fn deinit(self: *Self) void {
            self.unmanaged.deinit(self.allocator);
            self.* = undefined;
        }

        /// Empty the map, but keep the backing allocation for future use.
        /// This does *not* free keys or values! Be sure to
        /// release them if they need deinitialization before
        /// calling this function.
        pub fn clear_retaining_capacity(self: *Self) void {
            return self.unmanaged.clear_retaining_capacity();
        }

        /// Empty the map and release the backing allocation.
        /// This does *not* free keys or values! Be sure to
        /// release them if they need deinitialization before
        /// calling this function.
        pub fn clear_and_free(self: *Self) void {
            return self.unmanaged.clear_and_free(self.allocator);
        }

        /// Return the number of items in the map.
        pub fn count(self: Self) Size {
            return self.unmanaged.count();
        }

        /// Create an iterator over the entries in the map.
        /// The iterator is invalidated if the map is modified.
        pub fn iterator(self: *const Self) Iterator {
            return self.unmanaged.iterator();
        }

        /// Create an iterator over the keys in the map.
        /// The iterator is invalidated if the map is modified.
        pub fn key_iterator(self: Self) KeyIterator {
            return self.unmanaged.key_iterator();
        }

        /// Create an iterator over the values in the map.
        /// The iterator is invalidated if the map is modified.
        pub fn value_iterator(self: Self) ValueIterator {
            return self.unmanaged.value_iterator();
        }

        /// If key exists this function cannot fail.
        /// If there is an existing item with `key`, then the result's
        /// `Entry` pointers point to it, and found_existing is true.
        /// Otherwise, puts a new item with undefined value, and
        /// the `Entry` pointers point to it. Caller should then initialize
        /// the value (but not the key).
        pub fn get_or_put(self: *Self, key: K) Allocator.Error!GetOrPutResult {
            return self.unmanaged.get_or_put_context(self.allocator, key, self.ctx);
        }

        /// If key exists this function cannot fail.
        /// If there is an existing item with `key`, then the result's
        /// `Entry` pointers point to it, and found_existing is true.
        /// Otherwise, puts a new item with undefined key and value, and
        /// the `Entry` pointers point to it. Caller must then initialize
        /// the key and value.
        pub fn get_or_put_adapted(self: *Self, key: anytype, ctx: anytype) Allocator.Error!GetOrPutResult {
            return self.unmanaged.get_or_put_context_adapted(self.allocator, key, ctx, self.ctx);
        }

        /// If there is an existing item with `key`, then the result's
        /// `Entry` pointers point to it, and found_existing is true.
        /// Otherwise, puts a new item with undefined value, and
        /// the `Entry` pointers point to it. Caller should then initialize
        /// the value (but not the key).
        /// If a new entry needs to be stored, this function asserts there
        /// is enough capacity to store it.
        pub fn get_or_put_assume_capacity(self: *Self, key: K) GetOrPutResult {
            return self.unmanaged.get_or_put_assume_capacity_context(key, self.ctx);
        }

        /// If there is an existing item with `key`, then the result's
        /// `Entry` pointers point to it, and found_existing is true.
        /// Otherwise, puts a new item with undefined value, and
        /// the `Entry` pointers point to it. Caller must then initialize
        /// the key and value.
        /// If a new entry needs to be stored, this function asserts there
        /// is enough capacity to store it.
        pub fn get_or_put_assume_capacity_adapted(self: *Self, key: anytype, ctx: anytype) GetOrPutResult {
            return self.unmanaged.get_or_put_assume_capacity_adapted(key, ctx);
        }

        pub fn get_or_put_value(self: *Self, key: K, value: V) Allocator.Error!Entry {
            return self.unmanaged.get_or_put_value_context(self.allocator, key, value, self.ctx);
        }

        /// Increases capacity, guaranteeing that insertions up until the
        /// `expected_count` will not cause an allocation, and therefore cannot fail.
        pub fn ensure_total_capacity(self: *Self, expected_count: Size) Allocator.Error!void {
            return self.unmanaged.ensure_total_capacity_context(self.allocator, expected_count, self.ctx);
        }

        /// Increases capacity, guaranteeing that insertions up until
        /// `additional_count` **more** items will not cause an allocation, and
        /// therefore cannot fail.
        pub fn ensure_unused_capacity(self: *Self, additional_count: Size) Allocator.Error!void {
            return self.unmanaged.ensure_unused_capacity_context(self.allocator, additional_count, self.ctx);
        }

        /// Returns the number of total elements which may be present before it is
        /// no longer guaranteed that no allocations will be performed.
        pub fn capacity(self: Self) Size {
            return self.unmanaged.capacity();
        }

        /// Clobbers any existing data. To detect if a put would clobber
        /// existing data, see `get_or_put`.
        pub fn put(self: *Self, key: K, value: V) Allocator.Error!void {
            return self.unmanaged.put_context(self.allocator, key, value, self.ctx);
        }

        /// Inserts a key-value pair into the hash map, asserting that no previous
        /// entry with the same key is already present
        pub fn put_no_clobber(self: *Self, key: K, value: V) Allocator.Error!void {
            return self.unmanaged.put_no_clobber_context(self.allocator, key, value, self.ctx);
        }

        /// Asserts there is enough capacity to store the new key-value pair.
        /// Clobbers any existing data. To detect if a put would clobber
        /// existing data, see `get_or_put_assume_capacity`.
        pub fn put_assume_capacity(self: *Self, key: K, value: V) void {
            return self.unmanaged.put_assume_capacity_context(key, value, self.ctx);
        }

        /// Asserts there is enough capacity to store the new key-value pair.
        /// Asserts that it does not clobber any existing data.
        /// To detect if a put would clobber existing data, see `get_or_put_assume_capacity`.
        pub fn put_assume_capacity_no_clobber(self: *Self, key: K, value: V) void {
            return self.unmanaged.put_assume_capacity_no_clobber_context(key, value, self.ctx);
        }

        /// Inserts a new `Entry` into the hash map, returning the previous one, if any.
        pub fn fetch_put(self: *Self, key: K, value: V) Allocator.Error!?KV {
            return self.unmanaged.fetch_put_context(self.allocator, key, value, self.ctx);
        }

        /// Inserts a new `Entry` into the hash map, returning the previous one, if any.
        /// If insertion happens, asserts there is enough capacity without allocating.
        pub fn fetch_put_assume_capacity(self: *Self, key: K, value: V) ?KV {
            return self.unmanaged.fetch_put_assume_capacity_context(key, value, self.ctx);
        }

        /// Removes a value from the map and returns the removed kv pair.
        pub fn fetch_remove(self: *Self, key: K) ?KV {
            return self.unmanaged.fetch_remove_context(key, self.ctx);
        }

        pub fn fetch_remove_adapted(self: *Self, key: anytype, ctx: anytype) ?KV {
            return self.unmanaged.fetch_remove_adapted(key, ctx);
        }

        /// Finds the value associated with a key in the map
        pub fn get(self: Self, key: K) ?V {
            return self.unmanaged.get_context(key, self.ctx);
        }
        pub fn get_adapted(self: Self, key: anytype, ctx: anytype) ?V {
            return self.unmanaged.get_adapted(key, ctx);
        }

        pub fn get_ptr(self: Self, key: K) ?*V {
            return self.unmanaged.get_ptr_context(key, self.ctx);
        }
        pub fn get_ptr_adapted(self: Self, key: anytype, ctx: anytype) ?*V {
            return self.unmanaged.get_ptr_adapted(key, ctx);
        }

        /// Finds the actual key associated with an adapted key in the map
        pub fn get_key(self: Self, key: K) ?K {
            return self.unmanaged.get_key_context(key, self.ctx);
        }
        pub fn get_key_adapted(self: Self, key: anytype, ctx: anytype) ?K {
            return self.unmanaged.get_key_adapted(key, ctx);
        }

        pub fn get_key_ptr(self: Self, key: K) ?*K {
            return self.unmanaged.get_key_ptr_context(key, self.ctx);
        }
        pub fn get_key_ptr_adapted(self: Self, key: anytype, ctx: anytype) ?*K {
            return self.unmanaged.get_key_ptr_adapted(key, ctx);
        }

        /// Finds the key and value associated with a key in the map
        pub fn get_entry(self: Self, key: K) ?Entry {
            return self.unmanaged.get_entry_context(key, self.ctx);
        }

        pub fn get_entry_adapted(self: Self, key: anytype, ctx: anytype) ?Entry {
            return self.unmanaged.get_entry_adapted(key, ctx);
        }

        /// Check if the map contains a key
        pub fn contains(self: Self, key: K) bool {
            return self.unmanaged.contains_context(key, self.ctx);
        }

        pub fn contains_adapted(self: Self, key: anytype, ctx: anytype) bool {
            return self.unmanaged.contains_adapted(key, ctx);
        }

        /// If there is an `Entry` with a matching key, it is deleted from
        /// the hash map, and this function returns true.  Otherwise this
        /// function returns false.
        pub fn remove(self: *Self, key: K) bool {
            return self.unmanaged.remove_context(key, self.ctx);
        }

        pub fn remove_adapted(self: *Self, key: anytype, ctx: anytype) bool {
            return self.unmanaged.remove_adapted(key, ctx);
        }

        /// Delete the entry with key pointed to by key_ptr from the hash map.
        /// key_ptr is assumed to be a valid pointer to a key that is present
        /// in the hash map.
        pub fn remove_by_ptr(self: *Self, key_ptr: *K) void {
            self.unmanaged.remove_by_ptr(key_ptr);
        }

        /// Creates a copy of this map, using the same allocator
        pub fn clone(self: Self) Allocator.Error!Self {
            var other = try self.unmanaged.clone_context(self.allocator, self.ctx);
            return other.promote_context(self.allocator, self.ctx);
        }

        /// Creates a copy of this map, using a specified allocator
        pub fn clone_with_allocator(self: Self, new_allocator: Allocator) Allocator.Error!Self {
            var other = try self.unmanaged.clone_context(new_allocator, self.ctx);
            return other.promote_context(new_allocator, self.ctx);
        }

        /// Creates a copy of this map, using a specified context
        pub fn clone_with_context(self: Self, new_ctx: anytype) Allocator.Error!HashMap(K, V, @TypeOf(new_ctx), max_load_percentage) {
            var other = try self.unmanaged.clone_context(self.allocator, new_ctx);
            return other.promote_context(self.allocator, new_ctx);
        }

        /// Creates a copy of this map, using a specified allocator and context.
        pub fn clone_with_allocator_and_context(
            self: Self,
            new_allocator: Allocator,
            new_ctx: anytype,
        ) Allocator.Error!HashMap(K, V, @TypeOf(new_ctx), max_load_percentage) {
            var other = try self.unmanaged.clone_context(new_allocator, new_ctx);
            return other.promote_context(new_allocator, new_ctx);
        }

        /// Set the map to an empty state, making deinitialization a no-op, and
        /// returning a copy of the original.
        pub fn move(self: *Self) Self {
            self.unmanaged.pointer_stability.assert_unlocked();
            const result = self.*;
            self.unmanaged = .{};
            return result;
        }
    };
}

/// A HashMap based on open addressing and linear probing.
/// A lookup or modification typically incurs only 2 cache misses.
/// No order is guaranteed and any modification invalidates live iterators.
/// It achieves good performance with quite high load factors (by default,
/// grow is triggered at 80% full) and only one byte of overhead per element.
/// The struct itself is only 16 bytes for a small footprint. This comes at
/// the price of handling size with u32, which should be reasonable enough
/// for almost all uses.
/// Deletions are achieved with tombstones.
pub fn HashMapUnmanaged(
    comptime K: type,
    comptime V: type,
    comptime Context: type,
    comptime max_load_percentage: u64,
) type {
    if (max_load_percentage <= 0 or max_load_percentage >= 100)
        @compile_error("max_load_percentage must be between 0 and 100.");
    return struct {
        const Self = @This();

        comptime {
            verify_context(Context, K, K, u64, false);
        }

        // This is actually a midway pointer to the single buffer containing
        // a `Header` field, the `Metadata`s and `Entry`s.
        // At `-@size_of(Header)` is the Header field.
        // At `size_of(Metadata) * capacity + offset`, which is pointed to by
        // self.header().entries, is the array of entries.
        // This means that the hashmap only holds one live allocation, to
        // reduce memory fragmentation and struct size.
        /// Pointer to the metadata.
        metadata: ?[*]Metadata = null,

        /// Current number of elements in the hashmap.
        size: Size = 0,

        // Having a countdown to grow reduces the number of instructions to
        // execute when determining if the hashmap has enough capacity already.
        /// Number of available slots before a grow is needed to satisfy the
        /// `max_load_percentage`.
        available: Size = 0,

        /// Used to detect memory safety violations.
        pointer_stability: std.debug.SafetyLock = .{},

        // This is purely empirical and not a /very smart magic constant™/.
        /// Capacity of the first grow when bootstrapping the hashmap.
        const minimal_capacity = 8;

        // This hashmap is specially designed for sizes that fit in a u32.
        pub const Size = u32;

        // u64 hashes guarantee us that the fingerprint bits will never be used
        // to compute the index of a slot, maximizing the use of entropy.
        pub const Hash = u64;

        pub const Entry = struct {
            key_ptr: *K,
            value_ptr: *V,
        };

        pub const KV = struct {
            key: K,
            value: V,
        };

        const Header = struct {
            values: [*]V,
            keys: [*]K,
            capacity: Size,
        };

        /// Metadata for a slot. It can be in three states: empty, used or
        /// tombstone. Tombstones indicate that an entry was previously used,
        /// they are a simple way to handle removal.
        /// To this state, we add 7 bits from the slot's key hash. These are
        /// used as a fast way to disambiguate between entries without
        /// having to use the equality function. If two fingerprints are
        /// different, we know that we don't have to compare the keys at all.
        /// The 7 bits are the highest ones from a 64 bit hash. This way, not
        /// only we use the `log2(capacity)` lowest bits from the hash to determine
        /// a slot index, but we use 7 more bits to quickly resolve collisions
        /// when multiple elements with different hashes end up wanting to be in the same slot.
        /// Not using the equality function means we don't have to read into
        /// the entries array, likely avoiding a cache miss and a potentially
        /// costly function call.
        const Metadata = packed struct {
            const FingerPrint = u7;

            const free: FingerPrint = 0;
            const tombstone: FingerPrint = 1;

            fingerprint: FingerPrint = free,
            used: u1 = 0,

            const slot_free = @as(u8, @bit_cast(Metadata{ .fingerprint = free }));
            const slot_tombstone = @as(u8, @bit_cast(Metadata{ .fingerprint = tombstone }));

            pub fn is_used(self: Metadata) bool {
                return self.used == 1;
            }

            pub fn is_tombstone(self: Metadata) bool {
                return @as(u8, @bit_cast(self)) == slot_tombstone;
            }

            pub fn is_free(self: Metadata) bool {
                return @as(u8, @bit_cast(self)) == slot_free;
            }

            pub fn take_fingerprint(hash: Hash) FingerPrint {
                const hash_bits = @typeInfo(Hash).Int.bits;
                const fp_bits = @typeInfo(FingerPrint).Int.bits;
                return @as(FingerPrint, @truncate(hash >> (hash_bits - fp_bits)));
            }

            pub fn fill(self: *Metadata, fp: FingerPrint) void {
                self.used = 1;
                self.fingerprint = fp;
            }

            pub fn remove(self: *Metadata) void {
                self.used = 0;
                self.fingerprint = tombstone;
            }
        };

        comptime {
            assert(@size_of(Metadata) == 1);
            assert(@alignOf(Metadata) == 1);
        }

        pub const Iterator = struct {
            hm: *const Self,
            index: Size = 0,

            pub fn next(it: *Iterator) ?Entry {
                assert(it.index <= it.hm.capacity());
                if (it.hm.size == 0) return null;

                const cap = it.hm.capacity();
                const end = it.hm.metadata.? + cap;
                var metadata = it.hm.metadata.? + it.index;

                while (metadata != end) : ({
                    metadata += 1;
                    it.index += 1;
                }) {
                    if (metadata[0].is_used()) {
                        const key = &it.hm.keys()[it.index];
                        const value = &it.hm.values()[it.index];
                        it.index += 1;
                        return Entry{ .key_ptr = key, .value_ptr = value };
                    }
                }

                return null;
            }
        };

        pub const KeyIterator = FieldIterator(K);
        pub const ValueIterator = FieldIterator(V);

        fn FieldIterator(comptime T: type) type {
            return struct {
                len: usize,
                metadata: [*]const Metadata,
                items: [*]T,

                pub fn next(self: *@This()) ?*T {
                    while (self.len > 0) {
                        self.len -= 1;
                        const used = self.metadata[0].is_used();
                        const item = &self.items[0];
                        self.metadata += 1;
                        self.items += 1;
                        if (used) {
                            return item;
                        }
                    }
                    return null;
                }
            };
        }

        pub const GetOrPutResult = struct {
            key_ptr: *K,
            value_ptr: *V,
            found_existing: bool,
        };

        pub const Managed = HashMap(K, V, Context, max_load_percentage);

        pub fn promote(self: Self, allocator: Allocator) Managed {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call promote_context instead.");
            return promote_context(self, allocator, undefined);
        }

        pub fn promote_context(self: Self, allocator: Allocator, ctx: Context) Managed {
            return .{
                .unmanaged = self,
                .allocator = allocator,
                .ctx = ctx,
            };
        }

        /// Puts the hash map into a state where any method call that would
        /// cause an existing key or value pointer to become invalidated will
        /// instead trigger an assertion.
        ///
        /// An additional call to `lock_pointers` in such state also triggers an
        /// assertion.
        ///
        /// `unlock_pointers` returns the hash map to the previous state.
        pub fn lock_pointers(self: *Self) void {
            self.pointer_stability.lock();
        }

        /// Undoes a call to `lock_pointers`.
        pub fn unlock_pointers(self: *Self) void {
            self.pointer_stability.unlock();
        }

        fn is_under_max_load_percentage(size: Size, cap: Size) bool {
            return size * 100 < max_load_percentage * cap;
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            self.pointer_stability.assert_unlocked();
            self.deallocate(allocator);
            self.* = undefined;
        }

        fn capacity_for_size(size: Size) Size {
            var new_cap: u32 = @int_cast((@as(u64, size) * 100) / max_load_percentage + 1);
            new_cap = math.ceil_power_of_two(u32, new_cap) catch unreachable;
            return new_cap;
        }

        pub fn ensure_total_capacity(self: *Self, allocator: Allocator, new_size: Size) Allocator.Error!void {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call ensure_total_capacity_context instead.");
            return ensure_total_capacity_context(self, allocator, new_size, undefined);
        }
        pub fn ensure_total_capacity_context(self: *Self, allocator: Allocator, new_size: Size, ctx: Context) Allocator.Error!void {
            self.pointer_stability.lock();
            defer self.pointer_stability.unlock();
            if (new_size > self.size)
                try self.grow_if_needed(allocator, new_size - self.size, ctx);
        }

        pub fn ensure_unused_capacity(self: *Self, allocator: Allocator, additional_size: Size) Allocator.Error!void {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call ensure_unused_capacity_context instead.");
            return ensure_unused_capacity_context(self, allocator, additional_size, undefined);
        }
        pub fn ensure_unused_capacity_context(self: *Self, allocator: Allocator, additional_size: Size, ctx: Context) Allocator.Error!void {
            return ensure_total_capacity_context(self, allocator, self.count() + additional_size, ctx);
        }

        pub fn clear_retaining_capacity(self: *Self) void {
            self.pointer_stability.lock();
            defer self.pointer_stability.unlock();
            if (self.metadata) |_| {
                self.init_metadatas();
                self.size = 0;
                self.available = @truncate((self.capacity() * max_load_percentage) / 100);
            }
        }

        pub fn clear_and_free(self: *Self, allocator: Allocator) void {
            self.pointer_stability.lock();
            defer self.pointer_stability.unlock();
            self.deallocate(allocator);
            self.size = 0;
            self.available = 0;
        }

        pub fn count(self: Self) Size {
            return self.size;
        }

        fn header(self: Self) *Header {
            return @ptr_cast(@as([*]Header, @ptr_cast(@align_cast(self.metadata.?))) - 1);
        }

        fn keys(self: Self) [*]K {
            return self.header().keys;
        }

        fn values(self: Self) [*]V {
            return self.header().values;
        }

        pub fn capacity(self: Self) Size {
            if (self.metadata == null) return 0;

            return self.header().capacity;
        }

        pub fn iterator(self: *const Self) Iterator {
            return .{ .hm = self };
        }

        pub fn key_iterator(self: Self) KeyIterator {
            if (self.metadata) |metadata| {
                return .{
                    .len = self.capacity(),
                    .metadata = metadata,
                    .items = self.keys(),
                };
            } else {
                return .{
                    .len = 0,
                    .metadata = undefined,
                    .items = undefined,
                };
            }
        }

        pub fn value_iterator(self: Self) ValueIterator {
            if (self.metadata) |metadata| {
                return .{
                    .len = self.capacity(),
                    .metadata = metadata,
                    .items = self.values(),
                };
            } else {
                return .{
                    .len = 0,
                    .metadata = undefined,
                    .items = undefined,
                };
            }
        }

        /// Insert an entry in the map. Assumes it is not already present.
        pub fn put_no_clobber(self: *Self, allocator: Allocator, key: K, value: V) Allocator.Error!void {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call put_no_clobber_context instead.");
            return self.put_no_clobber_context(allocator, key, value, undefined);
        }
        pub fn put_no_clobber_context(self: *Self, allocator: Allocator, key: K, value: V, ctx: Context) Allocator.Error!void {
            {
                self.pointer_stability.lock();
                defer self.pointer_stability.unlock();
                try self.grow_if_needed(allocator, 1, ctx);
            }
            self.put_assume_capacity_no_clobber_context(key, value, ctx);
        }

        /// Asserts there is enough capacity to store the new key-value pair.
        /// Clobbers any existing data. To detect if a put would clobber
        /// existing data, see `get_or_put_assume_capacity`.
        pub fn put_assume_capacity(self: *Self, key: K, value: V) void {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call put_assume_capacity_context instead.");
            return self.put_assume_capacity_context(key, value, undefined);
        }
        pub fn put_assume_capacity_context(self: *Self, key: K, value: V, ctx: Context) void {
            const gop = self.get_or_put_assume_capacity_context(key, ctx);
            gop.value_ptr.* = value;
        }

        /// Insert an entry in the map. Assumes it is not already present,
        /// and that no allocation is needed.
        pub fn put_assume_capacity_no_clobber(self: *Self, key: K, value: V) void {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call put_assume_capacity_no_clobber_context instead.");
            return self.put_assume_capacity_no_clobber_context(key, value, undefined);
        }
        pub fn put_assume_capacity_no_clobber_context(self: *Self, key: K, value: V, ctx: Context) void {
            assert(!self.contains_context(key, ctx));

            const hash = ctx.hash(key);
            const mask = self.capacity() - 1;
            var idx: usize = @truncate(hash & mask);

            var metadata = self.metadata.? + idx;
            while (metadata[0].is_used()) {
                idx = (idx + 1) & mask;
                metadata = self.metadata.? + idx;
            }

            assert(self.available > 0);
            self.available -= 1;

            const fingerprint = Metadata.take_fingerprint(hash);
            metadata[0].fill(fingerprint);
            self.keys()[idx] = key;
            self.values()[idx] = value;

            self.size += 1;
        }

        /// Inserts a new `Entry` into the hash map, returning the previous one, if any.
        pub fn fetch_put(self: *Self, allocator: Allocator, key: K, value: V) Allocator.Error!?KV {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call fetch_put_context instead.");
            return self.fetch_put_context(allocator, key, value, undefined);
        }
        pub fn fetch_put_context(self: *Self, allocator: Allocator, key: K, value: V, ctx: Context) Allocator.Error!?KV {
            const gop = try self.get_or_put_context(allocator, key, ctx);
            var result: ?KV = null;
            if (gop.found_existing) {
                result = KV{
                    .key = gop.key_ptr.*,
                    .value = gop.value_ptr.*,
                };
            }
            gop.value_ptr.* = value;
            return result;
        }

        /// Inserts a new `Entry` into the hash map, returning the previous one, if any.
        /// If insertion happens, asserts there is enough capacity without allocating.
        pub fn fetch_put_assume_capacity(self: *Self, key: K, value: V) ?KV {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call fetch_put_assume_capacity_context instead.");
            return self.fetch_put_assume_capacity_context(key, value, undefined);
        }
        pub fn fetch_put_assume_capacity_context(self: *Self, key: K, value: V, ctx: Context) ?KV {
            const gop = self.get_or_put_assume_capacity_context(key, ctx);
            var result: ?KV = null;
            if (gop.found_existing) {
                result = KV{
                    .key = gop.key_ptr.*,
                    .value = gop.value_ptr.*,
                };
            }
            gop.value_ptr.* = value;
            return result;
        }

        /// If there is an `Entry` with a matching key, it is deleted from
        /// the hash map, and then returned from this function.
        pub fn fetch_remove(self: *Self, key: K) ?KV {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call fetch_remove_context instead.");
            return self.fetch_remove_context(key, undefined);
        }
        pub fn fetch_remove_context(self: *Self, key: K, ctx: Context) ?KV {
            return self.fetch_remove_adapted(key, ctx);
        }
        pub fn fetch_remove_adapted(self: *Self, key: anytype, ctx: anytype) ?KV {
            if (self.get_index(key, ctx)) |idx| {
                const old_key = &self.keys()[idx];
                const old_val = &self.values()[idx];
                const result = KV{
                    .key = old_key.*,
                    .value = old_val.*,
                };
                self.metadata.?[idx].remove();
                old_key.* = undefined;
                old_val.* = undefined;
                self.size -= 1;
                self.available += 1;
                return result;
            }

            return null;
        }

        /// Find the index containing the data for the given key.
        /// Whether this function returns null is almost always
        /// branched on after this function returns, and this function
        /// returns null/not null from separate code paths.  We
        /// want the optimizer to remove that branch and instead directly
        /// fuse the basic blocks after the branch to the basic blocks
        /// from this function.  To encourage that, this function is
        /// marked as inline.
        inline fn get_index(self: Self, key: anytype, ctx: anytype) ?usize {
            comptime verify_context(@TypeOf(ctx), @TypeOf(key), K, Hash, false);

            if (self.size == 0) {
                return null;
            }

            // If you get a compile error on this line, it means that your generic hash
            // function is invalid for these parameters.
            const hash = ctx.hash(key);
            // verify_context can't verify the return type of generic hash functions,
            // so we need to double-check it here.
            if (@TypeOf(hash) != Hash) {
                @compile_error("Context " ++ @type_name(@TypeOf(ctx)) ++ " has a generic hash function that returns the wrong type! " ++ @type_name(Hash) ++ " was expected, but found " ++ @type_name(@TypeOf(hash)));
            }
            const mask = self.capacity() - 1;
            const fingerprint = Metadata.take_fingerprint(hash);
            // Don't loop indefinitely when there are no empty slots.
            var limit = self.capacity();
            var idx = @as(usize, @truncate(hash & mask));

            var metadata = self.metadata.? + idx;
            while (!metadata[0].is_free() and limit != 0) {
                if (metadata[0].is_used() and metadata[0].fingerprint == fingerprint) {
                    const test_key = &self.keys()[idx];
                    // If you get a compile error on this line, it means that your generic eql
                    // function is invalid for these parameters.
                    const eql = ctx.eql(key, test_key.*);
                    // verify_context can't verify the return type of generic eql functions,
                    // so we need to double-check it here.
                    if (@TypeOf(eql) != bool) {
                        @compile_error("Context " ++ @type_name(@TypeOf(ctx)) ++ " has a generic eql function that returns the wrong type! bool was expected, but found " ++ @type_name(@TypeOf(eql)));
                    }
                    if (eql) {
                        return idx;
                    }
                }

                limit -= 1;
                idx = (idx + 1) & mask;
                metadata = self.metadata.? + idx;
            }

            return null;
        }

        pub fn get_entry(self: Self, key: K) ?Entry {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_entry_context instead.");
            return self.get_entry_context(key, undefined);
        }
        pub fn get_entry_context(self: Self, key: K, ctx: Context) ?Entry {
            return self.get_entry_adapted(key, ctx);
        }
        pub fn get_entry_adapted(self: Self, key: anytype, ctx: anytype) ?Entry {
            if (self.get_index(key, ctx)) |idx| {
                return Entry{
                    .key_ptr = &self.keys()[idx],
                    .value_ptr = &self.values()[idx],
                };
            }
            return null;
        }

        /// Insert an entry if the associated key is not already present, otherwise update preexisting value.
        pub fn put(self: *Self, allocator: Allocator, key: K, value: V) Allocator.Error!void {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call put_context instead.");
            return self.put_context(allocator, key, value, undefined);
        }
        pub fn put_context(self: *Self, allocator: Allocator, key: K, value: V, ctx: Context) Allocator.Error!void {
            const result = try self.get_or_put_context(allocator, key, ctx);
            result.value_ptr.* = value;
        }

        /// Get an optional pointer to the actual key associated with adapted key, if present.
        pub fn get_key_ptr(self: Self, key: K) ?*K {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_key_ptr_context instead.");
            return self.get_key_ptr_context(key, undefined);
        }
        pub fn get_key_ptr_context(self: Self, key: K, ctx: Context) ?*K {
            return self.get_key_ptr_adapted(key, ctx);
        }
        pub fn get_key_ptr_adapted(self: Self, key: anytype, ctx: anytype) ?*K {
            if (self.get_index(key, ctx)) |idx| {
                return &self.keys()[idx];
            }
            return null;
        }

        /// Get a copy of the actual key associated with adapted key, if present.
        pub fn get_key(self: Self, key: K) ?K {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_key_context instead.");
            return self.get_key_context(key, undefined);
        }
        pub fn get_key_context(self: Self, key: K, ctx: Context) ?K {
            return self.get_key_adapted(key, ctx);
        }
        pub fn get_key_adapted(self: Self, key: anytype, ctx: anytype) ?K {
            if (self.get_index(key, ctx)) |idx| {
                return self.keys()[idx];
            }
            return null;
        }

        /// Get an optional pointer to the value associated with key, if present.
        pub fn get_ptr(self: Self, key: K) ?*V {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_ptr_context instead.");
            return self.get_ptr_context(key, undefined);
        }
        pub fn get_ptr_context(self: Self, key: K, ctx: Context) ?*V {
            return self.get_ptr_adapted(key, ctx);
        }
        pub fn get_ptr_adapted(self: Self, key: anytype, ctx: anytype) ?*V {
            if (self.get_index(key, ctx)) |idx| {
                return &self.values()[idx];
            }
            return null;
        }

        /// Get a copy of the value associated with key, if present.
        pub fn get(self: Self, key: K) ?V {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_context instead.");
            return self.get_context(key, undefined);
        }
        pub fn get_context(self: Self, key: K, ctx: Context) ?V {
            return self.get_adapted(key, ctx);
        }
        pub fn get_adapted(self: Self, key: anytype, ctx: anytype) ?V {
            if (self.get_index(key, ctx)) |idx| {
                return self.values()[idx];
            }
            return null;
        }

        pub fn get_or_put(self: *Self, allocator: Allocator, key: K) Allocator.Error!GetOrPutResult {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_or_put_context instead.");
            return self.get_or_put_context(allocator, key, undefined);
        }
        pub fn get_or_put_context(self: *Self, allocator: Allocator, key: K, ctx: Context) Allocator.Error!GetOrPutResult {
            const gop = try self.get_or_put_context_adapted(allocator, key, ctx, ctx);
            if (!gop.found_existing) {
                gop.key_ptr.* = key;
            }
            return gop;
        }
        pub fn get_or_put_adapted(self: *Self, allocator: Allocator, key: anytype, key_ctx: anytype) Allocator.Error!GetOrPutResult {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_or_put_context_adapted instead.");
            return self.get_or_put_context_adapted(allocator, key, key_ctx, undefined);
        }
        pub fn get_or_put_context_adapted(self: *Self, allocator: Allocator, key: anytype, key_ctx: anytype, ctx: Context) Allocator.Error!GetOrPutResult {
            {
                self.pointer_stability.lock();
                defer self.pointer_stability.unlock();
                self.grow_if_needed(allocator, 1, ctx) catch |err| {
                    // If allocation fails, try to do the lookup anyway.
                    // If we find an existing item, we can return it.
                    // Otherwise return the error, we could not add another.
                    const index = self.get_index(key, key_ctx) orelse return err;
                    return GetOrPutResult{
                        .key_ptr = &self.keys()[index],
                        .value_ptr = &self.values()[index],
                        .found_existing = true,
                    };
                };
            }
            return self.get_or_put_assume_capacity_adapted(key, key_ctx);
        }

        pub fn get_or_put_assume_capacity(self: *Self, key: K) GetOrPutResult {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_or_put_assume_capacity_context instead.");
            return self.get_or_put_assume_capacity_context(key, undefined);
        }
        pub fn get_or_put_assume_capacity_context(self: *Self, key: K, ctx: Context) GetOrPutResult {
            const result = self.get_or_put_assume_capacity_adapted(key, ctx);
            if (!result.found_existing) {
                result.key_ptr.* = key;
            }
            return result;
        }
        pub fn get_or_put_assume_capacity_adapted(self: *Self, key: anytype, ctx: anytype) GetOrPutResult {
            comptime verify_context(@TypeOf(ctx), @TypeOf(key), K, Hash, false);

            // If you get a compile error on this line, it means that your generic hash
            // function is invalid for these parameters.
            const hash = ctx.hash(key);
            // verify_context can't verify the return type of generic hash functions,
            // so we need to double-check it here.
            if (@TypeOf(hash) != Hash) {
                @compile_error("Context " ++ @type_name(@TypeOf(ctx)) ++ " has a generic hash function that returns the wrong type! " ++ @type_name(Hash) ++ " was expected, but found " ++ @type_name(@TypeOf(hash)));
            }
            const mask = self.capacity() - 1;
            const fingerprint = Metadata.take_fingerprint(hash);
            var limit = self.capacity();
            var idx = @as(usize, @truncate(hash & mask));

            var first_tombstone_idx: usize = self.capacity(); // invalid index
            var metadata = self.metadata.? + idx;
            while (!metadata[0].is_free() and limit != 0) {
                if (metadata[0].is_used() and metadata[0].fingerprint == fingerprint) {
                    const test_key = &self.keys()[idx];
                    // If you get a compile error on this line, it means that your generic eql
                    // function is invalid for these parameters.
                    const eql = ctx.eql(key, test_key.*);
                    // verify_context can't verify the return type of generic eql functions,
                    // so we need to double-check it here.
                    if (@TypeOf(eql) != bool) {
                        @compile_error("Context " ++ @type_name(@TypeOf(ctx)) ++ " has a generic eql function that returns the wrong type! bool was expected, but found " ++ @type_name(@TypeOf(eql)));
                    }
                    if (eql) {
                        return GetOrPutResult{
                            .key_ptr = test_key,
                            .value_ptr = &self.values()[idx],
                            .found_existing = true,
                        };
                    }
                } else if (first_tombstone_idx == self.capacity() and metadata[0].is_tombstone()) {
                    first_tombstone_idx = idx;
                }

                limit -= 1;
                idx = (idx + 1) & mask;
                metadata = self.metadata.? + idx;
            }

            if (first_tombstone_idx < self.capacity()) {
                // Cheap try to lower probing lengths after deletions. Recycle a tombstone.
                idx = first_tombstone_idx;
                metadata = self.metadata.? + idx;
            }
            // We're using a slot previously free or a tombstone.
            self.available -= 1;

            metadata[0].fill(fingerprint);
            const new_key = &self.keys()[idx];
            const new_value = &self.values()[idx];
            new_key.* = undefined;
            new_value.* = undefined;
            self.size += 1;

            return GetOrPutResult{
                .key_ptr = new_key,
                .value_ptr = new_value,
                .found_existing = false,
            };
        }

        pub fn get_or_put_value(self: *Self, allocator: Allocator, key: K, value: V) Allocator.Error!Entry {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call get_or_put_value_context instead.");
            return self.get_or_put_value_context(allocator, key, value, undefined);
        }
        pub fn get_or_put_value_context(self: *Self, allocator: Allocator, key: K, value: V, ctx: Context) Allocator.Error!Entry {
            const res = try self.get_or_put_adapted(allocator, key, ctx);
            if (!res.found_existing) {
                res.key_ptr.* = key;
                res.value_ptr.* = value;
            }
            return Entry{ .key_ptr = res.key_ptr, .value_ptr = res.value_ptr };
        }

        /// Return true if there is a value associated with key in the map.
        pub fn contains(self: Self, key: K) bool {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call contains_context instead.");
            return self.contains_context(key, undefined);
        }
        pub fn contains_context(self: Self, key: K, ctx: Context) bool {
            return self.contains_adapted(key, ctx);
        }
        pub fn contains_adapted(self: Self, key: anytype, ctx: anytype) bool {
            return self.get_index(key, ctx) != null;
        }

        fn remove_by_index(self: *Self, idx: usize) void {
            self.metadata.?[idx].remove();
            self.keys()[idx] = undefined;
            self.values()[idx] = undefined;
            self.size -= 1;
            self.available += 1;
        }

        /// If there is an `Entry` with a matching key, it is deleted from
        /// the hash map, and this function returns true.  Otherwise this
        /// function returns false.
        pub fn remove(self: *Self, key: K) bool {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call remove_context instead.");
            return self.remove_context(key, undefined);
        }
        pub fn remove_context(self: *Self, key: K, ctx: Context) bool {
            return self.remove_adapted(key, ctx);
        }
        pub fn remove_adapted(self: *Self, key: anytype, ctx: anytype) bool {
            if (self.get_index(key, ctx)) |idx| {
                self.remove_by_index(idx);
                return true;
            }

            return false;
        }

        /// Delete the entry with key pointed to by key_ptr from the hash map.
        /// key_ptr is assumed to be a valid pointer to a key that is present
        /// in the hash map.
        pub fn remove_by_ptr(self: *Self, key_ptr: *K) void {
            // TODO: replace with pointer subtraction once supported by zig
            // if @size_of(K) == 0 then there is at most one item in the hash
            // map, which is assumed to exist as key_ptr must be valid.  This
            // item must be at index 0.
            const idx = if (@size_of(K) > 0)
                (@int_from_ptr(key_ptr) - @int_from_ptr(self.keys())) / @size_of(K)
            else
                0;

            self.remove_by_index(idx);
        }

        fn init_metadatas(self: *Self) void {
            @memset(@as([*]u8, @ptr_cast(self.metadata.?))[0 .. @size_of(Metadata) * self.capacity()], 0);
        }

        // This counts the number of occupied slots (not counting tombstones), which is
        // what has to stay under the max_load_percentage of capacity.
        fn load(self: Self) Size {
            const max_load = (self.capacity() * max_load_percentage) / 100;
            assert(max_load >= self.available);
            return @as(Size, @truncate(max_load - self.available));
        }

        fn grow_if_needed(self: *Self, allocator: Allocator, new_count: Size, ctx: Context) Allocator.Error!void {
            if (new_count > self.available) {
                try self.grow(allocator, capacity_for_size(self.load() + new_count), ctx);
            }
        }

        pub fn clone(self: Self, allocator: Allocator) Allocator.Error!Self {
            if (@size_of(Context) != 0)
                @compile_error("Cannot infer context " ++ @type_name(Context) ++ ", call clone_context instead.");
            return self.clone_context(allocator, @as(Context, undefined));
        }
        pub fn clone_context(self: Self, allocator: Allocator, new_ctx: anytype) Allocator.Error!HashMapUnmanaged(K, V, @TypeOf(new_ctx), max_load_percentage) {
            var other = HashMapUnmanaged(K, V, @TypeOf(new_ctx), max_load_percentage){};
            if (self.size == 0)
                return other;

            const new_cap = capacity_for_size(self.size);
            try other.allocate(allocator, new_cap);
            other.init_metadatas();
            other.available = @truncate((new_cap * max_load_percentage) / 100);

            var i: Size = 0;
            var metadata = self.metadata.?;
            const keys_ptr = self.keys();
            const values_ptr = self.values();
            while (i < self.capacity()) : (i += 1) {
                if (metadata[i].is_used()) {
                    other.put_assume_capacity_no_clobber_context(keys_ptr[i], values_ptr[i], new_ctx);
                    if (other.size == self.size)
                        break;
                }
            }

            return other;
        }

        /// Set the map to an empty state, making deinitialization a no-op, and
        /// returning a copy of the original.
        pub fn move(self: *Self) Self {
            self.pointer_stability.assert_unlocked();
            const result = self.*;
            self.* = .{};
            return result;
        }

        fn grow(self: *Self, allocator: Allocator, new_capacity: Size, ctx: Context) Allocator.Error!void {
            @setCold(true);
            const new_cap = @max(new_capacity, minimal_capacity);
            assert(new_cap > self.capacity());
            assert(std.math.is_power_of_two(new_cap));

            var map: Self = .{};
            try map.allocate(allocator, new_cap);
            errdefer comptime unreachable;
            map.pointer_stability.lock();
            map.init_metadatas();
            map.available = @truncate((new_cap * max_load_percentage) / 100);

            if (self.size != 0) {
                const old_capacity = self.capacity();
                for (
                    self.metadata.?[0..old_capacity],
                    self.keys()[0..old_capacity],
                    self.values()[0..old_capacity],
                ) |m, k, v| {
                    if (!m.is_used()) continue;
                    map.put_assume_capacity_no_clobber_context(k, v, ctx);
                    if (map.size == self.size) break;
                }
            }

            self.size = 0;
            self.pointer_stability = .{ .state = .unlocked };
            std.mem.swap(Self, self, &map);
            map.deinit(allocator);
        }

        fn allocate(self: *Self, allocator: Allocator, new_capacity: Size) Allocator.Error!void {
            const header_align = @alignOf(Header);
            const key_align = if (@size_of(K) == 0) 1 else @alignOf(K);
            const val_align = if (@size_of(V) == 0) 1 else @alignOf(V);
            const max_align = comptime @max(header_align, key_align, val_align);

            const new_cap: usize = new_capacity;
            const meta_size = @size_of(Header) + new_cap * @size_of(Metadata);
            comptime assert(@alignOf(Metadata) == 1);

            const keys_start = std.mem.align_forward(usize, meta_size, key_align);
            const keys_end = keys_start + new_cap * @size_of(K);

            const vals_start = std.mem.align_forward(usize, keys_end, val_align);
            const vals_end = vals_start + new_cap * @size_of(V);

            const total_size = std.mem.align_forward(usize, vals_end, max_align);

            const slice = try allocator.aligned_alloc(u8, max_align, total_size);
            const ptr: [*]u8 = @ptr_cast(slice.ptr);

            const metadata = ptr + @size_of(Header);

            const hdr = @as(*Header, @ptr_cast(@align_cast(ptr)));
            if (@size_of([*]V) != 0) {
                hdr.values = @ptr_cast(@align_cast((ptr + vals_start)));
            }
            if (@size_of([*]K) != 0) {
                hdr.keys = @ptr_cast(@align_cast((ptr + keys_start)));
            }
            hdr.capacity = new_capacity;
            self.metadata = @ptr_cast(@align_cast(metadata));
        }

        fn deallocate(self: *Self, allocator: Allocator) void {
            if (self.metadata == null) return;

            const header_align = @alignOf(Header);
            const key_align = if (@size_of(K) == 0) 1 else @alignOf(K);
            const val_align = if (@size_of(V) == 0) 1 else @alignOf(V);
            const max_align = comptime @max(header_align, key_align, val_align);

            const cap: usize = self.capacity();
            const meta_size = @size_of(Header) + cap * @size_of(Metadata);
            comptime assert(@alignOf(Metadata) == 1);

            const keys_start = std.mem.align_forward(usize, meta_size, key_align);
            const keys_end = keys_start + cap * @size_of(K);

            const vals_start = std.mem.align_forward(usize, keys_end, val_align);
            const vals_end = vals_start + cap * @size_of(V);

            const total_size = std.mem.align_forward(usize, vals_end, max_align);

            const slice = @as([*]align(max_align) u8, @align_cast(@ptr_cast(self.header())))[0..total_size];
            allocator.free(slice);

            self.metadata = null;
            self.available = 0;
        }

        /// This function is used in the debugger pretty formatters in tools/ to fetch the
        /// header type to facilitate fancy debug printing for this type.
        fn db_helper(self: *Self, hdr: *Header, entry: *Entry) void {
            _ = self;
            _ = hdr;
            _ = entry;
        }

        comptime {
            if (!builtin.strip_debug_info) {
                _ = &db_helper;
            }
        }
    };
}

const testing = std.testing;
const expect = std.testing.expect;
const expect_equal = std.testing.expect_equal;

test "basic usage" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    const count = 5;
    var i: u32 = 0;
    var total: u32 = 0;
    while (i < count) : (i += 1) {
        try map.put(i, i);
        total += i;
    }

    var sum: u32 = 0;
    var it = map.iterator();
    while (it.next()) |kv| {
        sum += kv.key_ptr.*;
    }
    try expect_equal(total, sum);

    i = 0;
    sum = 0;
    while (i < count) : (i += 1) {
        try expect_equal(i, map.get(i).?);
        sum += map.get(i).?;
    }
    try expect_equal(total, sum);
}

test "ensure_total_capacity" {
    var map = AutoHashMap(i32, i32).init(std.testing.allocator);
    defer map.deinit();

    try map.ensure_total_capacity(20);
    const initial_capacity = map.capacity();
    try testing.expect(initial_capacity >= 20);
    var i: i32 = 0;
    while (i < 20) : (i += 1) {
        try testing.expect(map.fetch_put_assume_capacity(i, i + 10) == null);
    }
    // shouldn't resize from put_assume_capacity
    try testing.expect(initial_capacity == map.capacity());
}

test "ensure_unused_capacity with tombstones" {
    var map = AutoHashMap(i32, i32).init(std.testing.allocator);
    defer map.deinit();

    var i: i32 = 0;
    while (i < 100) : (i += 1) {
        try map.ensure_unused_capacity(1);
        map.put_assume_capacity(i, i);
        _ = map.remove(i);
    }
}

test "clear_retaining_capacity" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    map.clear_retaining_capacity();

    try map.put(1, 1);
    try expect_equal(map.get(1).?, 1);
    try expect_equal(map.count(), 1);

    map.clear_retaining_capacity();
    map.put_assume_capacity(1, 1);
    try expect_equal(map.get(1).?, 1);
    try expect_equal(map.count(), 1);

    const cap = map.capacity();
    try expect(cap > 0);

    map.clear_retaining_capacity();
    map.clear_retaining_capacity();
    try expect_equal(map.count(), 0);
    try expect_equal(map.capacity(), cap);
    try expect(!map.contains(1));
}

test "grow" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    const growTo = 12456;

    var i: u32 = 0;
    while (i < growTo) : (i += 1) {
        try map.put(i, i);
    }
    try expect_equal(map.count(), growTo);

    i = 0;
    var it = map.iterator();
    while (it.next()) |kv| {
        try expect_equal(kv.key_ptr.*, kv.value_ptr.*);
        i += 1;
    }
    try expect_equal(i, growTo);

    i = 0;
    while (i < growTo) : (i += 1) {
        try expect_equal(map.get(i).?, i);
    }
}

test "clone" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    var a = try map.clone();
    defer a.deinit();

    try expect_equal(a.count(), 0);

    try a.put(1, 1);
    try a.put(2, 2);
    try a.put(3, 3);

    var b = try a.clone();
    defer b.deinit();

    try expect_equal(b.count(), 3);
    try expect_equal(b.get(1).?, 1);
    try expect_equal(b.get(2).?, 2);
    try expect_equal(b.get(3).?, 3);

    var original = AutoHashMap(i32, i32).init(std.testing.allocator);
    defer original.deinit();

    var i: u8 = 0;
    while (i < 10) : (i += 1) {
        try original.put_no_clobber(i, i * 10);
    }

    var copy = try original.clone();
    defer copy.deinit();

    i = 0;
    while (i < 10) : (i += 1) {
        try testing.expect(copy.get(i).? == i * 10);
    }
}

test "ensure_total_capacity with existing elements" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    try map.put(0, 0);
    try expect_equal(map.count(), 1);
    try expect_equal(map.capacity(), @TypeOf(map).Unmanaged.minimal_capacity);

    try map.ensure_total_capacity(65);
    try expect_equal(map.count(), 1);
    try expect_equal(map.capacity(), 128);
}

test "ensure_total_capacity satisfies max load factor" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    try map.ensure_total_capacity(127);
    try expect_equal(map.capacity(), 256);
}

test "remove" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try map.put(i, i);
    }

    i = 0;
    while (i < 16) : (i += 1) {
        if (i % 3 == 0) {
            _ = map.remove(i);
        }
    }
    try expect_equal(map.count(), 10);
    var it = map.iterator();
    while (it.next()) |kv| {
        try expect_equal(kv.key_ptr.*, kv.value_ptr.*);
        try expect(kv.key_ptr.* % 3 != 0);
    }

    i = 0;
    while (i < 16) : (i += 1) {
        if (i % 3 == 0) {
            try expect(!map.contains(i));
        } else {
            try expect_equal(map.get(i).?, i);
        }
    }
}

test "reverse removes" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try map.put_no_clobber(i, i);
    }

    i = 16;
    while (i > 0) : (i -= 1) {
        _ = map.remove(i - 1);
        try expect(!map.contains(i - 1));
        var j: u32 = 0;
        while (j < i - 1) : (j += 1) {
            try expect_equal(map.get(j).?, j);
        }
    }

    try expect_equal(map.count(), 0);
}

test "multiple removes on same metadata" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try map.put(i, i);
    }

    _ = map.remove(7);
    _ = map.remove(15);
    _ = map.remove(14);
    _ = map.remove(13);
    try expect(!map.contains(7));
    try expect(!map.contains(15));
    try expect(!map.contains(14));
    try expect(!map.contains(13));

    i = 0;
    while (i < 13) : (i += 1) {
        if (i == 7) {
            try expect(!map.contains(i));
        } else {
            try expect_equal(map.get(i).?, i);
        }
    }

    try map.put(15, 15);
    try map.put(13, 13);
    try map.put(14, 14);
    try map.put(7, 7);
    i = 0;
    while (i < 16) : (i += 1) {
        try expect_equal(map.get(i).?, i);
    }
}

test "put and remove loop in random order" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    var keys = std.ArrayList(u32).init(std.testing.allocator);
    defer keys.deinit();

    const size = 32;
    const iterations = 100;

    var i: u32 = 0;
    while (i < size) : (i += 1) {
        try keys.append(i);
    }
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    while (i < iterations) : (i += 1) {
        random.shuffle(u32, keys.items);

        for (keys.items) |key| {
            try map.put(key, key);
        }
        try expect_equal(map.count(), size);

        for (keys.items) |key| {
            _ = map.remove(key);
        }
        try expect_equal(map.count(), 0);
    }
}

test "remove one million elements in random order" {
    const Map = AutoHashMap(u32, u32);
    const n = 1000 * 1000;
    var map = Map.init(std.heap.page_allocator);
    defer map.deinit();

    var keys = std.ArrayList(u32).init(std.heap.page_allocator);
    defer keys.deinit();

    var i: u32 = 0;
    while (i < n) : (i += 1) {
        keys.append(i) catch unreachable;
    }

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();
    random.shuffle(u32, keys.items);

    for (keys.items) |key| {
        map.put(key, key) catch unreachable;
    }

    random.shuffle(u32, keys.items);
    i = 0;
    while (i < n) : (i += 1) {
        const key = keys.items[i];
        _ = map.remove(key);
    }
}

test "put" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        try map.put(i, i);
    }

    i = 0;
    while (i < 16) : (i += 1) {
        try expect_equal(map.get(i).?, i);
    }

    i = 0;
    while (i < 16) : (i += 1) {
        try map.put(i, i * 16 + 1);
    }

    i = 0;
    while (i < 16) : (i += 1) {
        try expect_equal(map.get(i).?, i * 16 + 1);
    }
}

test "put_assume_capacity" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    try map.ensure_total_capacity(20);
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        map.put_assume_capacity_no_clobber(i, i);
    }

    i = 0;
    var sum = i;
    while (i < 20) : (i += 1) {
        sum += map.get_ptr(i).?.*;
    }
    try expect_equal(sum, 190);

    i = 0;
    while (i < 20) : (i += 1) {
        map.put_assume_capacity(i, 1);
    }

    i = 0;
    sum = i;
    while (i < 20) : (i += 1) {
        sum += map.get(i).?;
    }
    try expect_equal(sum, 20);
}

test "repeat put_assume_capacity/remove" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    try map.ensure_total_capacity(20);
    const limit = map.unmanaged.available;

    var i: u32 = 0;
    while (i < limit) : (i += 1) {
        map.put_assume_capacity_no_clobber(i, i);
    }

    // Repeatedly delete/insert an entry without resizing the map.
    // Put to different keys so entries don't land in the just-freed slot.
    i = 0;
    while (i < 10 * limit) : (i += 1) {
        try testing.expect(map.remove(i));
        if (i % 2 == 0) {
            map.put_assume_capacity_no_clobber(limit + i, i);
        } else {
            map.put_assume_capacity(limit + i, i);
        }
    }

    i = 9 * limit;
    while (i < 10 * limit) : (i += 1) {
        try expect_equal(map.get(limit + i), i);
    }
    try expect_equal(map.unmanaged.available, 0);
    try expect_equal(map.unmanaged.count(), limit);
}

test "get_or_put" {
    var map = AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        try map.put(i * 2, 2);
    }

    i = 0;
    while (i < 20) : (i += 1) {
        _ = try map.get_or_put_value(i, 1);
    }

    i = 0;
    var sum = i;
    while (i < 20) : (i += 1) {
        sum += map.get(i).?;
    }

    try expect_equal(sum, 30);
}

test "basic hash map usage" {
    var map = AutoHashMap(i32, i32).init(std.testing.allocator);
    defer map.deinit();

    try testing.expect((try map.fetch_put(1, 11)) == null);
    try testing.expect((try map.fetch_put(2, 22)) == null);
    try testing.expect((try map.fetch_put(3, 33)) == null);
    try testing.expect((try map.fetch_put(4, 44)) == null);

    try map.put_no_clobber(5, 55);
    try testing.expect((try map.fetch_put(5, 66)).?.value == 55);
    try testing.expect((try map.fetch_put(5, 55)).?.value == 66);

    const gop1 = try map.get_or_put(5);
    try testing.expect(gop1.found_existing == true);
    try testing.expect(gop1.value_ptr.* == 55);
    gop1.value_ptr.* = 77;
    try testing.expect(map.get_entry(5).?.value_ptr.* == 77);

    const gop2 = try map.get_or_put(99);
    try testing.expect(gop2.found_existing == false);
    gop2.value_ptr.* = 42;
    try testing.expect(map.get_entry(99).?.value_ptr.* == 42);

    const gop3 = try map.get_or_put_value(5, 5);
    try testing.expect(gop3.value_ptr.* == 77);

    const gop4 = try map.get_or_put_value(100, 41);
    try testing.expect(gop4.value_ptr.* == 41);

    try testing.expect(map.contains(2));
    try testing.expect(map.get_entry(2).?.value_ptr.* == 22);
    try testing.expect(map.get(2).? == 22);

    const rmv1 = map.fetch_remove(2);
    try testing.expect(rmv1.?.key == 2);
    try testing.expect(rmv1.?.value == 22);
    try testing.expect(map.fetch_remove(2) == null);
    try testing.expect(map.remove(2) == false);
    try testing.expect(map.get_entry(2) == null);
    try testing.expect(map.get(2) == null);

    try testing.expect(map.remove(3) == true);
}

test "get_or_put_adapted" {
    const AdaptedContext = struct {
        fn eql(self: @This(), adapted_key: []const u8, test_key: u64) bool {
            _ = self;
            return std.fmt.parse_int(u64, adapted_key, 10) catch unreachable == test_key;
        }
        fn hash(self: @This(), adapted_key: []const u8) u64 {
            _ = self;
            const key = std.fmt.parse_int(u64, adapted_key, 10) catch unreachable;
            return (AutoContext(u64){}).hash(key);
        }
    };
    var map = AutoHashMap(u64, u64).init(testing.allocator);
    defer map.deinit();

    const keys = [_][]const u8{
        "1231",
        "4564",
        "7894",
        "1132",
        "65235",
        "95462",
        "0112305",
        "00658",
        "0",
        "2",
    };

    var real_keys: [keys.len]u64 = undefined;

    inline for (keys, 0..) |key_str, i| {
        const result = try map.get_or_put_adapted(key_str, AdaptedContext{});
        try testing.expect(!result.found_existing);
        real_keys[i] = std.fmt.parse_int(u64, key_str, 10) catch unreachable;
        result.key_ptr.* = real_keys[i];
        result.value_ptr.* = i * 2;
    }

    try testing.expect_equal(map.count(), keys.len);

    inline for (keys, 0..) |key_str, i| {
        const result = map.get_or_put_assume_capacity_adapted(key_str, AdaptedContext{});
        try testing.expect(result.found_existing);
        try testing.expect_equal(real_keys[i], result.key_ptr.*);
        try testing.expect_equal(@as(u64, i) * 2, result.value_ptr.*);
        try testing.expect_equal(real_keys[i], map.get_key_adapted(key_str, AdaptedContext{}).?);
    }
}

test "ensure_unused_capacity" {
    var map = AutoHashMap(u64, u64).init(testing.allocator);
    defer map.deinit();

    try map.ensure_unused_capacity(32);
    const capacity = map.capacity();
    try map.ensure_unused_capacity(32);

    // Repeated ensure_unused_capacity() calls with no insertions between
    // should not change the capacity.
    try testing.expect_equal(capacity, map.capacity());
}

test "remove_by_ptr" {
    var map = AutoHashMap(i32, u64).init(testing.allocator);
    defer map.deinit();

    var i: i32 = undefined;

    i = 0;
    while (i < 10) : (i += 1) {
        try map.put(i, 0);
    }

    try testing.expect(map.count() == 10);

    i = 0;
    while (i < 10) : (i += 1) {
        const key_ptr = map.get_key_ptr(i);
        try testing.expect(key_ptr != null);

        if (key_ptr) |ptr| {
            map.remove_by_ptr(ptr);
        }
    }

    try testing.expect(map.count() == 0);
}

test "remove_by_ptr 0 sized key" {
    var map = AutoHashMap(u0, u64).init(testing.allocator);
    defer map.deinit();

    try map.put(0, 0);

    try testing.expect(map.count() == 1);

    const key_ptr = map.get_key_ptr(0);
    try testing.expect(key_ptr != null);

    if (key_ptr) |ptr| {
        map.remove_by_ptr(ptr);
    }

    try testing.expect(map.count() == 0);
}

test "repeat fetch_remove" {
    var map = AutoHashMapUnmanaged(u64, void){};
    defer map.deinit(testing.allocator);

    try map.ensure_total_capacity(testing.allocator, 4);

    map.put_assume_capacity(0, {});
    map.put_assume_capacity(1, {});
    map.put_assume_capacity(2, {});
    map.put_assume_capacity(3, {});

    // fetch_remove() should make slots available.
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try testing.expect(map.fetch_remove(3) != null);
        map.put_assume_capacity(3, {});
    }

    try testing.expect(map.get(0) != null);
    try testing.expect(map.get(1) != null);
    try testing.expect(map.get(2) != null);
    try testing.expect(map.get(3) != null);
}

test "get_or_put allocation failure" {
    var map: std.StringHashMapUnmanaged(void) = .{};
    try testing.expect_error(error.OutOfMemory, map.get_or_put(std.testing.failing_allocator, "hello"));
}
