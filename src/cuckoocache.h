// Copyright (c) 2016 Jeremy Rubin
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_CUCKOOCACHE_H_
#define _BITCOIN_CUCKOOCACHE_H_

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <vector>


/** namespace CuckooCache provides high performance cache primitives
 *
 * Summary:
 *
 * 1) bit_packed_atomic_flags is bit-packed atomic flags for garbage collection
 *
 * 2) cache is a cache which is performant in memory usage and lookup speed. It
 * is lockfree for erase operations. Elements are lazily erased on the next
 * insert.
 */
namespace CuckooCache
{
/** bit_packed_atomic_flags implements a container for garbage collection flags
 * that is only thread unsafe on calls to setup. This class bit-packs collection
 * flags for memory efficiency.
 *
 * All operations are std::memory_order_relaxed so external mechanisms must
 * ensure that writes and reads are properly synchronized.
 *
 * On setup(n), all bits up to n are marked as collected.
 *
 * Under the hood, because it is an 8-bit type, it makes sense to use a multiple
 * of 8 for setup, but it will be safe if that is not the case as well.
 *
 */
class bit_packed_atomic_flags
{
    struct impl : std::atomic<uint8_t> {
        impl() : std::atomic<uint8_t>(0xFF){};
        impl(const impl& other) : std::atomic<uint8_t>(other.load()){};
    };
    std::unique_ptr<impl[]> mem;

public:
    /** No default constructor as there must be some size */
    bit_packed_atomic_flags() = delete;

    /**
     * bit_packed_atomic_flags constructor creates memory to sufficiently
     * keep track of garbage collection information for size entries.
     */
    bit_packed_atomic_flags(uint32_t size)
    {
        // pad out the size if needed
        size = (size + 7) / 8;
        mem.reset(new impl[size]);
    };

    /** setup marks all entries and ensures that bit_packed_atomic_flags can store
     * at least size entries
     */
    inline void setup(uint32_t b)
    {
        bit_packed_atomic_flags d(b);
        std::swap(mem, d.mem);
    }

    /** set sets an entry as discardable.  */
    inline void set(uint32_t s)
    {
        mem[s >> 3].fetch_or(1 << (s & 7), std::memory_order_relaxed);
    }

    /**  unset marks an entry as something that should not be overwritten  */
    inline void unset(uint32_t s)
    {
        mem[s >> 3].fetch_and(~(1 << (s & 7)), std::memory_order_relaxed);
    }

    /** queries the set for discardability at n*/
    inline bool is_set(uint32_t s)
    {
        return (1 << (s & 7)) & mem[s >> 3].load(std::memory_order_relaxed);
    }
};

/** cache implements a cache with properties similar to a cuckoo-set
 *
 *  The cache is able to hold up to (~(uint32_t) 1) elements.
 *
 *  Read Operations:
 *      - contains(*, false)
 *
 *  Read/Erase Operations:
 *      - contains(*, true)
 *      - allow_erase()
 *
 *  Write Operations:
 *      - setup()
 *      - setup_bytes()
 *      - insert()
 *      - please_keep()
 *      - rehash()
 *
 *  Synchronization Free Operations:
 *      - invalid()
 *      - compute_hash()
 *
 * User Must Guarantee:
 *
 * 1) Write Requires synchronized access (e.g., a lock)
 * 2) Read Requires no concurrent Write, synchronized with the last insert.
 * 3) Erase requires no concurrent Write, synchronized with last insert.
 * 4) An Eraser must release all Erases before allowing a new Writer.
 *
 *
 * Note on function names:
 *   - The name "allow_erase" is used because the real discard happens later.
 *   - The name "please_keep" is used because keys may be erased anyways on insert.
 *
 * @tparam Key should be a POD type that is 32-alignable
 * @tparam Hash should be a function/callable which takes a Key and an Offset and
 * extracts a hash from it. Should return high-entropy hashes for
 * Hash(k, 0) and Hash(k, 1).
 */
template <typename Key, typename Hash>
class cache
{
    static_assert((sizeof(Key) % 32) == 0, "Invalid Key Size.");

public:
private:
    /** set stores all the keys */
    std::vector<Key> set;

    /** The bit_packed_atomic_flags array is marked mutable because we want
     * garbage collection to be allowed to occur from const methods */
    mutable bit_packed_atomic_flags collection_flags;

    /** size stores the total available slots in the hash table */
    uint32_t size;

    /** depth_limit determines how many keys insert should try to replace.
     * Should be set to log2(n)*/
    uint8_t depth_limit;

    /** hash_function is a const instance of the hash function. It cannot be
     * static or initialized at call time as it may have internal state (such as
     * a nonce).
     * */
    const Hash hash_function;

    /** convenience for not having to write out the modulus everywhere.
     */
    template <uint8_t n>
    inline uint32_t compute_hash(const Key& t) const
    {
        return hash_function.template operator()<n>(t) % size;
    }

    /* end returns a constexpr index that can never be inserted to */
    constexpr uint32_t invalid() const
    {
        return ~(uint32_t)1;
    }

    /** allow_erase marks the key at index n as discardable. Threadsafe
     * without any concurrent insert. */
    inline void allow_erase(uint32_t n) const
    {
        collection_flags.set(n);
    }

    /** please_keep marks the key at index n as an entry that should be kept.
     * Threadsafe without any concurrent insert. */
    inline void please_keep(uint32_t n) const
    {
        collection_flags.unset(n);
    }

public:
    /** You must always construct a cache with some elements, otherwise
     * operations may segfault. By default, construct with 2
     * elements.
     */
    cache() : set(), collection_flags(0), size(0), depth_limit(0), hash_function()
    {
        setup(2);
    }

    /** setup adjusts the container to store new_size elements and clears the cache if new_size != size
     **/
    void setup(uint32_t new_size)
    {
        // n must be at least one otherwise errors can occur.
        new_size = std::max((uint32_t)2, (uint32_t)((new_size + 1) & (~(uint32_t)1)));
        if (new_size == size)
            return;
        size = new_size;
        set.resize(size);
        collection_flags.setup(size);
        depth_limit = std::max((uint8_t)1, static_cast<uint8_t>(std::log2(static_cast<float>(size))));
    }

    /** setup bytes is a convenience function which accounts for internal
     * memory usage when deciding how many elements to store. It isn't perfect
     * because it doesn't account for MallocUsage of collection_flags or set.
     * This difference is small/0, so we ignore it.
     */
    void setup_bytes(size_t bytes)
    {
        size_t bytes_free = bytes - sizeof(cache<Key, Hash>);
        size_t n = 0;
        n = (8 * bytes_free) / (8 * sizeof(Key) + sizeof(std::atomic<uint8_t>));
        setup(n);
    }

    /** insert loops at most depth_limit times trying to insert a hash
     * at various locations in the set via a variant of the Cuckoo Algorithm
     * with two hash locations.
     *
     * It drops the last tried element if it runs out of depth before
     * encountering an open slot.
     *
     */
    inline void insert(const Key& keyIn)
    {
        Key k = keyIn;
        uint32_t last_loc = invalid();
        uint32_t locs[2] = {compute_hash<0>(k), compute_hash<1>(k)};
        // Make sure we have not already inserted this key
        // If we have, make sure that it does not get deleted
        for (uint32_t loc : locs)
            if (set[loc] == k)
                return please_keep(loc);
        for (uint8_t depth = 0; depth < depth_limit; ++depth) {
            // First try to insert to an empty slot, if one exists
            for (uint32_t loc : locs) {
                if (!collection_flags.is_set(loc))
                    continue;
                set[loc] = k;
                please_keep(loc);
                return;
            }
            /** Swap with the element at the location that was
            * not the last one looked at. Example:
            *
            * 1) On first iter, always false so defaults to locs[0]
            * 2) Second iter, last_loc == locs[0] so will go to locs[1]
            *
            * This prevents moving the element we just put in.
            */
            last_loc = last_loc == locs[0] ? locs[1] : locs[0];
            std::swap(set[last_loc], k);

            // Recompute the locs -- unfortunately happens one too many times!
            locs[0] = compute_hash<0>(k);
            locs[1] = compute_hash<1>(k);
        }
    }

    /* contains iterates through the hash locations for a given key
     * and checks to see if it is present.
     *
     * contains does not check garbage collected state (in other words,
     * garbage is only collected when the space is needed), so:
     *
     * insert(x);
     * contains(x, true);
     * return contains(x, false);
     *
     * executed on a single thread will always return true!
     *
     * This is a great property for re-org performance for example.
     *
     * contains returns a bool set true if the element was found.
     */

    inline bool contains(const Key& k, const bool erase) const
    {
        if (erase) {
            uint32_t locs[2] = {compute_hash<0>(k), compute_hash<1>(k)};
            for (uint32_t loc : locs)
                if (set[loc] == k) {
                    allow_erase(loc);
                    return true;
                }
            return false;
        } else
            return set[compute_hash<0>(k)] == k || set[compute_hash<1>(k)] == k;
    }
};
}

#endif
