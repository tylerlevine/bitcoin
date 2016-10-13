// Copyright (c) 2016 Jeremy Rubin
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_CUCKOOCACHE_H_
#define _BITCOIN_CUCKOOCACHE_H_

#include <algorithm>
#include <atomic>
#include <cstring>
#include <cmath>
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
    std::unique_ptr<std::atomic<uint8_t>[]> mem;

public:
    /** No default constructor as there must be some size */
    bit_packed_atomic_flags() = delete;

    /**
     * bit_packed_atomic_flags constructor creates memory to sufficiently
     * keep track of garbage collection information for size entries.
     *
     * @param size the number of elements to allocate space for
     *
     * @post bit_set, bit_unset, and bit_is_set function properly forall x. x <
     * size
     * @post All calls to bit_is_set (without subsequent bit_unset) will return
     * true.
     */
    bit_packed_atomic_flags(uint32_t size)
    {
        // pad out the size if needed
        size = (size + 7) / 8;
        mem.reset(new std::atomic<uint8_t>[size]);
        for (uint32_t i = 0; i < size; ++i)
            mem[size].store(0xFF);
    };

    /** setup marks all entries and ensures that bit_packed_atomic_flags can store
     * at least size entries
     *
     * @param b the number of elements to allocate space for
     * @post bit_set, bit_unset, and bit_is_set function properly forall x. x <
     * b
     * @post All calls to bit_is_set (without subsequent bit_unset) will return
     * true.
     */
    inline void setup(uint32_t b)
    {
        bit_packed_atomic_flags d(b);
        std::swap(mem, d.mem);
    }

    /** bit_set sets an entry as discardable. 
     *
     * @param s the index of the entry to bit_set.
     * @post immediately subsequent call (assuming proper external memory
     * ordering) to bit_is_set(s) == true.
     *
     */
    inline void bit_set(uint32_t s)
    {
        mem[s >> 3].fetch_or(1 << (s & 7), std::memory_order_relaxed);
    }

    /**  bit_unset marks an entry as something that should not be overwritten  
     *
     * @param s the index of the entry to bit_unset.
     * @post immediately subsequent call (assuming proper external memory
     * ordering) to bit_is_set(s) == false.
     */
    inline void bit_unset(uint32_t s)
    {
        mem[s >> 3].fetch_and(~(1 << (s & 7)), std::memory_order_relaxed);
    }

    /** bit_is_set queries the table for discardability at s
     *
     * @param s the index of the entry to read.
     * @returns if the bit at index s was set.
     * */
    inline bool bit_is_set(uint32_t s) const
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
 *   - The name "please_keep" is used because elements may be erased anyways on insert.
 *
 * @tparam Element should be a POD type that is 32-alignable
 * @tparam Hash should be a function/callable which takes a template parameter
 * hash_select and an Element and extracts a hash from it. Should return
 * high-entropy hashes for `Hash h; h<0>(e) and h<1>(e)`.
 */
template <typename Element, typename Hash>
class cache
{
    static_assert((sizeof(Element) % 32) == 0, "Invalid Element Size.");

public:
private:
    /** table stores all the elements */
    std::vector<Element> table;

    /** The bit_packed_atomic_flags array is marked mutable because we want
     * garbage collection to be allowed to occur from const methods */
    mutable bit_packed_atomic_flags collection_flags;

    /** size stores the total available slots in the hash table */
    uint32_t size;

    /** depth_limit determines how many elements insert should try to replace.
     * Should be set to log2(n)*/
    uint8_t depth_limit;

    /** hash_function is a const instance of the hash function. It cannot be
     * static or initialized at call time as it may have internal state (such as
     * a nonce).
     * */
    const Hash hash_function;

    /** convenience for not having to write this out everywhere we compute a
     * hash.
     *
     * @tparam hash_select the hash position
     * @param e the element whose hash will be returned
     * @returns a deterministic hash of type unint32_t derived from e.
     */
    template <uint8_t hash_select>
    inline uint32_t compute_hash(const Element& e) const
    {
        return hash_function.template operator()<hash_select>(e) % size;
    }

    /* end
     * @returns a constexpr index that can never be inserted to */
    constexpr uint32_t invalid() const
    {
        return ~(uint32_t)1;
    }

    /** allow_erase marks the element at index n as discardable. Threadsafe
     * without any concurrent insert.
     * @param n the index to allow erasure of
     */
    inline void allow_erase(uint32_t n) const
    {
        collection_flags.bit_set(n);
    }

    /** please_keep marks the element at index n as an entry that should be kept.
     * Threadsafe without any concurrent insert.
     * @param n the index to prioritize keeping
     */
    inline void please_keep(uint32_t n) const
    {
        collection_flags.bit_unset(n);
    }

public:
    /** You must always construct a cache with some elements, otherwise
     * operations may segfault. By default, construct with 2
     * elements.
     */
    cache() : table(), collection_flags(0), size(0), depth_limit(0), hash_function()
    {
        setup(2);
    }

    /** setup adjusts the container to store new_size elements and clears the cache if new_size != size
     *
     * @param new_size the new number of elements to store
     * @post if new_size == size, no effect
     * @post if new_size != size, inserted elements may not be at their correct
     * location and all collection_flags are set. (still possible for some
     * elements to not be evicted).
     **/
    void setup(uint32_t new_size)
    {
        // n must be at least one otherwise errors can occur.
        new_size = std::max((uint32_t)2, (uint32_t)((new_size + 1) & (~(uint32_t)1)));
        if (new_size == size)
            return;
        size = new_size;
        table.resize(size);
        collection_flags.setup(size);
        depth_limit = std::max((uint8_t)1, static_cast<uint8_t>(std::log2(static_cast<float>(size))));
    }

    /** setup_bytes is a convenience function which accounts for internal
     * memory usage when deciding how many elements to store. It isn't perfect
     * because it doesn't account for MallocUsage of collection_flags or table.
     * This difference is small or 0, so we ignore it.
     *
     * @param bytes the approximate number of bytes to use for this data
     * structure.
     */
    void setup_bytes(size_t bytes)
    {
        size_t bytes_free = bytes - sizeof(cache<Element, Hash>);
        size_t n = 0;
        n = (8 * bytes_free) / (8 * sizeof(Element) + sizeof(std::atomic<uint8_t>));
        setup(n);
    }

    /** insert loops at most depth_limit times trying to insert a hash
     * at various locations in the table via a variant of the Cuckoo Algorithm
     * with two hash locations.
     *
     * It drops the last tried element if it runs out of depth before
     * encountering an open slot.
     *
     * Thus
     *
     * insert(x);
     * return contains(x, false);
     *
     * is not guaranteed to return true.
     *
     * @param e the element to insert
     * @post one of the following: All previously inserted elements and e are
     * now in the table, one previously inserted element is evicted from the
     * table, the entry attempted to be inserted is evicted.
     *
     */
    inline void insert(Element e)
    {
        uint32_t last_loc = invalid();
        uint32_t locs[2] = {compute_hash<0>(e), compute_hash<1>(e)};
        // Make sure we have not already inserted this element
        // If we have, make sure that it does not get deleted
        for (uint32_t loc : locs)
            if (table[loc] == e)
                return please_keep(loc);
        for (uint8_t depth = 0; depth < depth_limit; ++depth) {
            // First try to insert to an empty slot, if one exists
            for (uint32_t loc : locs) {
                if (!collection_flags.bit_is_set(loc))
                    continue;
                table[loc] = std::move(e);
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
            *
            * The swap is not a move -- we must switch onto the evicted element
            * for the next iteration.
            */
            last_loc = last_loc == locs[0] ? locs[1] : locs[0];
            std::swap(table[last_loc], e);

            // Recompute the locs -- unfortunately happens one too many times!
            locs[0] = compute_hash<0>(e);
            locs[1] = compute_hash<1>(e);
        }
    }

    /* contains iterates through the hash locations for a given element
     * and checks to see if it is present.
     *
     * contains does not check garbage collected state (in other words,
     * garbage is only collected when the space is needed), so:
     *
     * insert(x);
     * if (contains(x, true))
     *     return contains(x, false);
     * else
     *     return true;
     *
     * executed on a single thread will always return true!
     *
     * This is a great property for re-org performance for example.
     *
     * contains returns a bool set true if the element was found.
     *
     * @param e the element to check
     * @param erase
     *
     * @post if erase is true and the element is found, then the garbage collect
     * flag is set
     * @returns true if the element is found, false otherwise
     */
    inline bool contains(const Element& e, const bool erase) const
    {
        if (erase) {
            uint32_t locs[2] = {compute_hash<0>(e), compute_hash<1>(e)};
            for (uint32_t loc : locs)
                if (table[loc] == e) {
                    allow_erase(loc);
                    return true;
                }
            return false;
        } else
            return table[compute_hash<0>(e)] == e || table[compute_hash<1>(e)] == e;
    }
};
}

#endif
