// Copyright (c) 2016 Jeremy Rubin
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _BITCOIN_CUCKOOCACHE_H_
#define _BITCOIN_CUCKOOCACHE_H_

#include <atomic>
#include <vector>


/**
 * garbage_collect_flag is a subtype of a std::atomic<uint8_t> 
 * with the benfit that it can be copy constructed, allowing
 * dynamically initialized vectors to be used. This means 
 * it is not entirely thread safe if the container (e.g., std::vector)
 * resizes after startup.
 */
struct garbage_collect_flag : std::atomic<uint8_t> {
    garbage_collect_flag() : std::atomic<uint8_t>(0xff){};
    garbage_collect_flag(const garbage_collect_flag& s) : std::atomic<uint8_t>(s.load()){};
};

/** garbage_collect_flags implements a container for garbage collection flags
 * that is only thread unsafe on calls to resize. This class bit-packs collection
 * flags for memory efficiency.
 *
 * All operations are std::memory_order_relaxed so external mechanisms must
 * ensure that writes and reads are properly synchronized.
 *
 * On resize(n), all bits up to n are marked.
 *
 * Under the hood, because it is an 8-bit type, it makes sense to use a multiple
 * of 8 for resize, but it will be safe if that is not the case as well.
 *
 */
template <typename size_type_in>
class garbage_collect_flags
{
    std::vector<garbage_collect_flag> v;

public:
    typedef size_type_in size_type;
    void resize(size_type s)
    {
        v.resize((s / 8) + (s% 8 != 0));
    }
    void shrink_to_fit()
    {
        v.shrink_to_fit();
    }
    void mark(size_type s)
    {
        v[s / 8].fetch_or(1 << (s % 8), std::memory_order_relaxed);
    }

    void unmark(size_type s)
    {
        v[s / 8].fetch_and(~(1 << (s % 8)), std::memory_order_relaxed);
    }

    bool is_marked(size_type s)
    {
        return (1 << (s % 8)) & v[s / 8].load(std::memory_order_relaxed);
    }
};
template <typename Key, typename Hash>
class CuckooCache
{
public:
    // (Most Of) The standard container typedefs, for compatibility, along with
    // a few custom ones pertaining to this class (made private)
    typedef Key key_type;
    typedef key_type value_type;

private:
    typedef std::vector<value_type> underlying_storage;
    typedef uint8_t recursion_limit_type;

public:
    typedef uint32_t size_type;
    typedef Hash hasher;
    typedef typename underlying_storage::reference reference;
    typedef typename underlying_storage::const_reference const_reference;
    typedef typename underlying_storage::pointer pointer;
    typedef typename underlying_storage::const_pointer const_pointer;
    typedef typename underlying_storage::iterator iterator;
    typedef typename underlying_storage::const_iterator const_iterator;

private:
    /** set stores all the keys */
    underlying_storage set;

    /** The garbage_collect_flags array is marked mutable because we want
     * garbage collection to be allowed to occur from const methods */
    mutable garbage_collect_flags<size_type> flags;

    /** size stores the total available slots in the hash table */
    size_type size;

    /** hash_function is a const instance of the hash function. It cannot be
     * static or initialized at call time as it may have internal state (such as
     * a nonce.
     * */
    const hasher hash_function;


    /** convenience for not having to write out the modulus everywhere.
     */
    recursion_limit_type depth_limit;
    inline size_type compute_hash(const value_type& t, recursion_limit_type n) const
    {
        return hash_function(t, n) % size;
    }

public:
    /** We must always construct a CuckooCache with one element, otherwise
     * it could segfault on operations.
     */
    CuckooCache() : set(), flags(), size(), hash_function(), depth_limit()
    {
        resize(1);
    }

    /** Insert loops depth_limit times trying to insert a hash
     * at various locations via the Cuckoo Algorithm
     *
     * It drops the last element if it runs out of depth.
     *
     * Note: We trample on the passed in key to avoid having to copy any memory
     * needlessly. There is no use case which actually needs that key to be 
     * preserved
     *
     * TODO: This is technically sub optimal because we swap onto the last hash
     * looked at but we should swap onto the one that will result in minimal
     * moves of memory. That's expensive to compute though, so "whatever".
     *
     * TODO: Optimize the order of hashes we look at; theoretically there
     * could be some value in giving insert and find for speed
     *
     *
     */
    void insert(value_type& t)
    {
        for (auto i = 0; i < depth_limit; ++i) {
            // Check that the value has not been inserted already,
            // and make sure it's not marked for garbage collection
            auto it = find(t);
            if (it != end())
                return un_garbage_collect(it);
            size_type h;
            // Look at each hash location and put it in if
            // we find a collected location
            for (auto n = 0; n < 4; ++n) {
                h = compute_hash(t, n);
                // In this case, it is safe to just replace the old data
                if (flags.is_marked(h)) {
                    set[h] = t;
                    flags.unmark(h);
                    return;
                }
            }
            // We must make a copy because the table must be in accurate state before recursing
            std::swap(set[h], t);
        }
    }

    /* find iterates through the hash locations for a given key
     * and checks to see if it is present. 
     *
     * Find does not check garbage collected state, so
     *
     * auto it = find(x)
     * garbage_collect(it)
     * contains(x)
     *
     * executed on a single thread will always succed
     *
     * find returns a const_iterator to the value if it is
     * present, or end() if it is not.
     */
    const_iterator find(const value_type& t) const
    {
        for (auto n = 0; n < 4; ++n) {
            size_type h = compute_hash(t, n);
            if (set[h] == t)
                return set.begin() + h;
        }
        return set.end();
    }
    /* contains is much like find, but returns a bool rather
     * than an iterator
     */
    bool contains(const value_type& t) const
    {
        for (auto i = 0; i < 4; ++i)
            if (set[compute_hash(t, i)] == t)
                return true;
        return false;
    }
    /* end returns a const_iterator to the end of the set. Used to check that
     * find did not return anything */
    const_iterator end()
    {
        return set.end();
    }

    /** rehash reinserts every element of the set into itself. This should be
     * done after a resize, and never really otherwise. It is not guaranteed
     * to preserve all values currently in the set
     */
    void rehash(size_type nprev)
    {
        for (auto i = 0; i < nprev; ++i) {
            if (flags.is_marked(i))
                continue;
            value_type t = set[i];
            insert(t);
        }
    }

    /** resize asjusts the container to store up to new_size elements
     *
     * Not thread safe. Invalidates all iterators.
     *
     * If new_size < old_size, the array is first rehashed and then resized such
     * that all elements can be reinserted.
     *
     * If new_size > old_size the array is resized and then rehashed such that
     * all memory locations should be valid.
     *
     * If new_size == old_size, has no effect.
     *
     *
     **/
    void resize(size_type new_size)
    {
        // n must be at least one otherwise errors can occur.
        new_size = std::max(1u, new_size);
        if (new_size == size)
            return;

        bool downsizing = new_size < size;
        if (downsizing) {
            auto nprev = size;
            size = new_size;
            // rehash before clearing the memory with
            // a resize
            rehash(nprev);
            set.resize(size);
            flags.resize(size);

            flags.shrink_to_fit();
            set.shrink_to_fit();
        } else {
            // resize before increasing memory so all locations exist
            set.resize(new_size);
            flags.resize(new_size);
            rehash(size);
            size = new_size;
        }
        depth_limit = static_cast<recursion_limit_type>(std::log2(static_cast<float>(size)));
    }

    /** resize bytes is a convenience function which accounts for internal
     * memory usage when deciding how many elements to store.
     */
    void resize_bytes(size_t bytes)
    {
        auto bytes_free = bytes - sizeof(CuckooCache<key_type, hasher>);
        auto n = (8 * bytes_free) / (8 * sizeof(value_type) + sizeof(std::atomic<uint8_t>));
        resize(n);
    }


    /** garbage_collect marks a key or iterator to a key as collected. Threadsafe without any concurrent insert. */
    void garbage_collect(const value_type& t) const
    {
        auto it = find(t);
        if (it != end())
            garbage_collect(it);
    }
    void garbage_collect(const_iterator it) const
    {
        flags.mark(it - set.begin());
    }

    /** un-garbage_collect marks a key or iterator to a key as not-collected. Threadsafe without any concurrent insert. */
    void un_garbage_collect(const value_type& t) const
    {
        auto it = find(t);
        if (it != end())
            garbage_collect(it);
    }
    void un_garbage_collect(const_iterator it) const
    {
        flags.unmark(it - set.begin());
    }
};

#endif
